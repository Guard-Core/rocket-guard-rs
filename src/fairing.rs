//! The `on_request` / `on_ignite` / `on_response` fairing.

use crate::response;
use crate::scan::{
    GuardEngine, Metadata, Verdict, metadata_threat_verdict, metadata_verdict,
    record_gate_decision, stage_decision,
};
use guard_core_engine::detection_exclusions::DetectionExclusionConfig;
use guard_core_engine::distributed::{BanStore, SlidingWindowStore};
use guard_core_engine::geo::GeoIpHandler;
use guard_core_engine::ip_ban::{IpBanConfig, IpBanManager, ViolationCounters};
use guard_core_engine::ip_gate::IpGateVerdict;
use guard_core_engine::rate_limit::{RateLimitConfig, RateLimiter};
use guard_core_rs::cloud_provider::CloudProviderStage;
use guard_core_rs::custom_checks::CustomChecksStage;
use guard_core_rs::emergency_mode::EmergencyModeStage;
use guard_core_rs::events::SecurityEventBus;
use guard_core_rs::geo::GeoStage;
use guard_core_rs::headers_auth::HeadersAuthStage;
use guard_core_rs::https_enforcement::HttpsEnforcementStage;
use guard_core_rs::process_response::{RequestBits, ResponseBits, ResponseProcessor};
use guard_core_rs::request_logging::{RequestLoggingStage, RequestLoggingStageConfig};
use guard_core_rs::responses::{CustomErrorResponses, OnBlockHook};
use guard_core_rs::route_gates::{ReferrerStage, TimeWindowStage};
use guard_core_rs::tower::RouteRateResolver;
use guard_core_rs::tower::{ObservabilityConfig, RateLimitStage, RateLimitStageConfig};
use guard_core_rs::user_agent::UserAgentStage;
use rocket::Data;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::Status;
use rocket::request::Request;
use rocket::response::Response;
use rocket::{Build, Rocket};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

/// Screens every request through the Guard engine before routing, and
/// registers the catchers that render the refusals.
///
/// Attach it to the application, then add [`crate::BlockGuard`] (routes
/// without a body) or [`crate::GuardBody`] (routes with one) to the handler
/// signatures that should be protected:
///
/// ```
/// use rocket::{get, routes, Build, Rocket};
/// use rocket_guard_rs::{BlockGuard, GuardFairing, default_config};
///
/// #[get("/hello")]
/// fn hello(_guard: BlockGuard) -> &'static str {
///     "hello"
/// }
///
/// fn rocket() -> Rocket<Build> {
///     rocket::build()
///         .attach(GuardFairing::new(default_config()))
///         .mount("/", routes![hello])
/// }
/// ```
///
/// Why two pieces: a Rocket fairing cannot abort a request (there is no
/// short-circuit return from `on_request`), so the fairing can only record a
/// verdict. Enforcement needs a request guard, the one Rocket extension point
/// that can refuse a request before its handler runs. Rocket's own source
/// makes the same call: request fairings were considered for this and
/// rejected in favor of request guards.
///
/// ## What runs where
///
/// | Phase | Work |
/// |---|---|
/// | `on_ignite` | Manage the engine configuration; register the `403`/`413`/`500` catchers for statuses the application has not claimed |
/// | `on_request` | Scan path, query, and header views; stash the verdict in request-local state |
/// | `on_response` | Rewrite a `404` to the guarded `403` when the stashed verdict is a threat |
///
/// The body view is **not** scanned here. Rocket's `Data::peek` is capped at
/// 512 bytes, so a fairing can only ever see a prefix of the body, and a
/// truncated scan is a bypass vector. Body scanning lives in
/// [`crate::GuardBody`], which owns the data stream and can read to the cap.
///
/// The `on_response` rewrite exists because a threat to a path that matches
/// no route would otherwise answer `404`: no guard runs, so nothing can block
/// it earlier. A `404` is proof that no route handler ran, so rewriting it
/// cannot discard work an application did. Threats that reach a route
/// *without* a guard argument are only scanned, not blocked: in Rocket,
/// protection is per-route, and that is what the guard argument is for.
/// The `agent_stats` answer (the reference middleware property shape):
/// whether an agent is wired and whether its start degraded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentStats {
    /// Whether an agent handler is wired (`enabled`).
    pub enabled: bool,
    /// Whether the agent started with failures (`degraded`).
    pub degraded: bool,
}

#[derive(Clone)]
pub struct GuardFairing {
    engine: GuardEngine,
    ip_gate: Option<guard_core_engine::ip_gate::IpGateConfig>,
    route_tiers: Option<RouteRateResolver>,
    geo_handler: Option<std::sync::Arc<dyn GeoIpHandler>>,
    events: Option<std::sync::Arc<SecurityEventBus>>,
    observability: Option<ObservabilityConfig>,
    on_block: Option<OnBlockHook>,
    /// The reference `custom_response_modifier`: mutates the response
    /// view the response pass composes before it leaves the pipeline.
    response_modifier: Option<guard_core_engine::payload::ResponseModifierFn>,
    /// The reference `on_error` best-effort hook.
    on_error: Option<guard_core_rs::responses::OnErrorHook>,
    custom_error_responses: CustomErrorResponses,
    passive_mode: bool,
    /// The reference `enable_penetration_detection`: the global scan
    /// toggle (the reference default `true`).
    penetration_detection_enabled: bool,
    distributed: Option<(std::sync::Arc<dyn SlidingWindowStore>, String, bool)>,
    distributed_ban_store: Option<std::sync::Arc<dyn BanStore>>,
    detection_exclusions: Option<DetectionExclusionConfig>,
    route_exclusions: Option<crate::scan::RouteExclusionsResolver>,
    /// Check 2: the emergency-mode stage.
    emergency_mode: Option<EmergencyModeStage>,
    /// Check 3: the HTTPS-enforcement stage.
    https_enforcement: Option<HttpsEnforcementStage>,
    /// Check 4: the request-logging stage (compose-only, never blocks).
    request_logging: Option<RequestLoggingStage>,
    /// Checks 6 + 7: the required-headers and authentication stage.
    headers_auth: Option<HeadersAuthStage>,
    /// Check 8: the route referrer gate.
    referrer_gate: Option<ReferrerStage>,
    /// Check 9 + 17: the custom-checks stage.
    custom_checks: Option<CustomChecksStage>,
    /// Check 10: the route time-window gate.
    time_window_gate: Option<TimeWindowStage>,
    /// Check 12b: the geo country-blocking stage.
    geo_blocking: Option<GeoStage>,
    /// Check 13: the cloud-provider blocking stage.
    cloud_provider: Option<CloudProviderStage>,
    /// Check 14: the blocked user-agent stage.
    user_agent: Option<UserAgentStage>,
    /// The response-side pass (behavioral return rules + security headers
    /// + CORS) applied to every response the fairing touches.
    response_processor: Option<Arc<ResponseProcessor>>,
    /// The reference `exclude_paths`: request paths that bypass the whole
    /// pipeline (the docs/static carve-out).
    exclude_paths: Vec<String>,
    /// The reference `RouteConfigResolver` (`(method, path) ->
    /// Option<Arc<RouteConfig>>`): the per-route carrier the pipeline
    /// consumes. An `Arc<RouteConfig>` stashed with
    /// `set_route_config` wins over the resolver.
    route_configs: Option<guard_core_engine::route_config::RouteConfigResolver>,
    scan_fn: crate::ScanFn,
    /// The cloud-refresh seam the `refresh_cloud_ip_ranges` maintenance
    /// call drives (the reference `refresh_cloud_ip_ranges`'s handler).
    cloud_refresh: Option<(
        std::sync::Arc<guard_core_rs::geo_lifecycle::CloudRefreshScheduler>,
        std::sync::Arc<guard_core_engine::cloud_provider::CloudIpTable>,
    )>,
}

impl GuardFairing {
    /// Build the fairing from an engine detection configuration.
    ///
    /// The body cap starts at `config.max_full_scan_bytes` (262,144 bytes in
    /// [`crate::default_config`]), the engine's own full-scan cap, and no IP
    /// gate is configured (one can be added with
    /// [`GuardFairing::with_ip_gate`]).
    #[must_use]
    pub fn new(config: guard_core_engine::detect::DetectConfig) -> Self {
        Self {
            engine: GuardEngine::new(config),
            ip_gate: None,
            route_tiers: None,
            geo_handler: None,
            events: None,
            observability: None,
            on_block: None,
            custom_error_responses: CustomErrorResponses::new(),
            response_modifier: None,
            on_error: None,
            passive_mode: false,
            penetration_detection_enabled: true,
            distributed: None,
            distributed_ban_store: None,
            detection_exclusions: None,
            route_exclusions: None,
            emergency_mode: None,
            https_enforcement: None,
            request_logging: None,
            headers_auth: None,
            referrer_gate: None,
            custom_checks: None,
            time_window_gate: None,
            geo_blocking: None,
            cloud_provider: None,
            user_agent: None,
            response_processor: None,
            exclude_paths: Vec::new(),
            route_configs: None,
            scan_fn: guard_core_engine::detection_exclusions::scan_request,
            cloud_refresh: None,
        }
    }

    /// Build the fairing with [`crate::default_config`].
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(crate::default_config())
    }

    /// The request paths that bypass the whole pipeline (the reference
    /// `exclude_paths` carve-out, exact path match).
    #[must_use]
    pub fn exclude_paths(&self) -> &[String] {
        &self.exclude_paths
    }

    /// Set the `exclude_paths` carve-out.
    #[must_use]
    pub fn with_exclude_paths(mut self, paths: Vec<String>) -> Self {
        self.exclude_paths = paths;
        self
    }

    /// Install the reference `RouteConfigResolver` (the
    /// [`guard_core_engine::route_config::RouteConfig`] carrier):
    /// `(method, path) -> Option<Arc<RouteConfig>>`. The resolved route's
    /// knobs apply on top of the global config for that route only, the
    /// reference `RouteConfigResolver` semantics: `bypassed_checks` (and
    /// the `"all"` wildcard) skip the named reference checks,
    /// `require_https` forces the reference `301`, `max_request_size`
    /// replaces the body cap, `blocked_user_agents` is evaluated
    /// additively before the global filter, the rate-limit group becomes
    /// the route's tier, and the detection-exclusion group resolves
    /// through the engine's detection view. An `Arc<RouteConfig>`
    /// stashed with [`crate::set_route_config`] wins over the resolver.
    #[must_use]
    pub fn with_route_configs(
        mut self,
        resolver: guard_core_engine::route_config::RouteConfigResolver,
    ) -> Self {
        self.route_configs = Some(resolver);
        self
    }

    /// Build the fairing from the unified `SecurityConfig`
    /// (the reference configuration surface): every field the fairing
    /// consumes maps onto the wired stage or knob it owns, in one place,
    /// with the reference semantics - the same consumption the tower
    /// adapter ships under `GuardLayer::from_security_config`.
    ///
    /// The stages that need a host-provided collaborator (the geo handler,
    /// the distributed stores, the event bus, the custom checks, the
    /// time-window and referrer resolvers) stay opt-in through their own
    /// builders: the config carries no such object.
    ///
    /// # Errors
    ///
    /// [`crate::GuardConfigError`] when an engine constructor rejects a
    /// value (an invalid IP/CIDR list entry, a zero rate-limit knob, or a
    /// ReDoS-unsafe blocked user-agent pattern).
    #[allow(clippy::too_many_lines)]
    pub fn from_security_config(
        config: &guard_core_engine::security_config::SecurityConfig,
    ) -> Result<Self, crate::GuardConfigError> {
        let mut fairing = Self::new(guard_core_engine::detect::DetectConfig {
            max_content_length: config.detection_max_content_length,
            max_full_scan_bytes: config.detection_max_body_inspect_bytes,
            preserve_attack_patterns: config.detection_preserve_attack_patterns,
            semantic_threshold: config.detection_semantic_threshold,
            threat_score_threshold: config.detection_threat_score_threshold,
            binary_min_run_length: config.detection_binary_min_run_length,
            max_scan_values: config.detection_max_scan_values,
            max_scan_chars: config.detection_max_scan_chars,
            max_json_depth: config.detection_max_json_depth,
        })
        .with_passive_mode(config.passive_mode)
        .with_penetration_detection(config.enable_penetration_detection)
        .with_exclude_paths(config.exclude_paths.clone());

        if config.whitelist.is_some()
            || !config.blacklist.is_empty()
            || !config.exempt_ips.is_empty()
        {
            fairing = fairing.with_ip_gate(guard_core_engine::ip_gate::IpGateConfig::new(
                config.whitelist.clone().unwrap_or_default(),
                config.blacklist.iter().cloned(),
                config.exempt_ips.iter().cloned(),
            )?);
        }

        if config.enable_rate_limiting {
            let limiter = RateLimiter::new(RateLimitConfig {
                enable_rate_limiting: true,
                rate_limit: config.rate_limit,
                rate_limit_window: config.rate_limit_window,
                ..RateLimitConfig::default()
            })?;
            fairing = fairing.with_rate_limiting(limiter);
        }

        if config.enable_ip_banning {
            fairing = fairing.with_ip_banning(IpBanManager::new(), config.ip_ban_config());
        }

        // Check 3: the global HTTPS arm; `X-Forwarded-Proto` trust rides
        // the same knobs the reference reads them from.
        fairing = fairing.with_https_enforcement(
            HttpsEnforcementStage::builder(
                guard_core_rs::https_enforcement::HttpsEnforcementStageConfig {
                    enforce_https: config.enforce_https,
                    trust_x_forwarded_proto: config.trust_x_forwarded_proto,
                    passive_mode: config.passive_mode,
                },
            )
            .build()?,
        );

        if config.emergency_mode || !config.emergency_whitelist.is_empty() {
            fairing = fairing.with_emergency_mode(
                EmergencyModeStage::builder(
                    guard_core_rs::emergency_mode::EmergencyModeStageConfig {
                        emergency_mode: config.emergency_mode,
                        passive_mode: config.passive_mode,
                    },
                )
                .emergency_whitelist(config.emergency_whitelist.iter().cloned())
                .build()?,
            );
        }

        if !config.custom_error_responses.is_empty() {
            fairing = fairing.with_custom_error_responses(
                config
                    .custom_error_responses
                    .iter()
                    .map(|(status, body)| (*status, body.clone()))
                    .collect(),
            );
        }

        if let Some(hook) = config.on_block.clone() {
            fairing = fairing.with_on_block(hook);
        }

        if !config.excluded_detection_headers.is_empty()
            || !config.excluded_detection_params.is_empty()
            || !config.excluded_detection_body_fields.is_empty()
            || !config.enabled_detection_categories.is_empty()
        {
            fairing = fairing.with_detection_exclusions(DetectionExclusionConfig {
                excluded_detection_headers: config
                    .excluded_detection_headers
                    .iter()
                    .cloned()
                    .collect(),
                excluded_detection_params: config
                    .excluded_detection_params
                    .iter()
                    .cloned()
                    .collect(),
                excluded_detection_body_fields: config
                    .excluded_detection_body_fields
                    .iter()
                    .cloned()
                    .collect(),
                enabled_detection_categories: (!config.enabled_detection_categories.is_empty())
                    .then(|| {
                        config
                            .enabled_detection_categories
                            .iter()
                            .cloned()
                            .collect()
                    }),
                detection_scan_body: Some(config.detection_scan_body),
            });
        }

        if let Some(level) = config.log_request_level {
            // The reference construction gate: the request-logging check
            // exists only when `log_request_level` is set.
            fairing =
                fairing.with_request_logging(RequestLoggingStage::new(RequestLoggingStageConfig {
                    log_request_level: Some(crate::map_log_level(level)),
                    muted_check_logs: Some(config.muted_check_logs.iter().cloned().collect()),
                    sensitive: guard_core_rs::redact::SensitiveNames::new(
                        Some(&config.log_sensitive_headers.iter().cloned().collect()),
                        Some(&config.log_sensitive_params.iter().cloned().collect()),
                        Some(&config.log_sensitive_body_fields.iter().cloned().collect()),
                    ),
                }));
        }

        if let Some(level) = config.log_suspicious_level {
            fairing = fairing.with_observability(ObservabilityConfig {
                log_suspicious_level: Some(crate::map_log_level(level)),
                log_request_level: config.log_request_level.map(crate::map_log_level),
                log_country_check_level: config.log_country_check_level.map(crate::map_log_level),
                muted_check_logs: Some(config.muted_check_logs.iter().cloned().collect()),
                sensitive: guard_core_rs::redact::SensitiveNames::new(
                    Some(&config.log_sensitive_headers.iter().cloned().collect()),
                    Some(&config.log_sensitive_params.iter().cloned().collect()),
                    Some(&config.log_sensitive_body_fields.iter().cloned().collect()),
                ),
            });
        } else if let Some(country_level) = config.log_country_check_level {
            // Country verdicts compose even without a suspicious level.
            fairing = fairing.with_observability(ObservabilityConfig {
                log_suspicious_level: None,
                log_request_level: config.log_request_level.map(crate::map_log_level),
                log_country_check_level: Some(crate::map_log_level(country_level)),
                muted_check_logs: Some(config.muted_check_logs.iter().cloned().collect()),
                sensitive: guard_core_rs::redact::SensitiveNames::new(
                    Some(&config.log_sensitive_headers.iter().cloned().collect()),
                    Some(&config.log_sensitive_params.iter().cloned().collect()),
                    Some(&config.log_sensitive_body_fields.iter().cloned().collect()),
                ),
            });
        }

        if !config.blocked_user_agents.is_empty() {
            fairing = fairing.with_user_agent(
                UserAgentStage::builder(guard_core_rs::user_agent::UserAgentStageConfig {
                    // The error arm takes its own line: the coverage
                    // mapping attributes the `?` return to the function
                    // exit, so an inline `?` here renders count 0 forever.
                    blocked_user_agents: guard_core_engine::user_agent::UserAgentFilter::new(
                        config.blocked_user_agents.iter().cloned(),
                    )
                    .map_err(crate::GuardConfigError::from)?,
                    ip_ban: config.ip_ban_config(),
                    passive_mode: config.passive_mode,
                })
                .build()?,
            );
        }

        let wants_headers = config.security_headers.enabled;
        if wants_headers || config.enable_cors || !config.global_behavior_rules.is_empty() {
            let cors = config
                .enable_cors
                .then(|| guard_core_engine::cors::CorsConfig {
                    enabled: true,
                    allow_origins: config.cors_allow_origins.clone(),
                    allow_methods: config.cors_allow_methods.clone(),
                    allow_headers: config.cors_allow_headers.clone(),
                    allow_credentials: config.cors_allow_credentials,
                    max_age: config.cors_max_age,
                });
            fairing = fairing.with_response_processor(ResponseProcessor::new(
                wants_headers.then_some(config.security_headers.clone()),
                cors,
                config.global_behavior_rules.clone(),
                Arc::new(std::sync::Mutex::new(
                    guard_core_engine::behavior::BehaviorTracker::new(),
                )),
                IpBanManager::new(),
                config.behavior_scan_response_body,
                config.behavior_max_response_body_inspect_bytes,
                config.passive_mode,
            ));
        }

        Ok(fairing)
    }

    /// Install the global IP gate: a `whitelist`/`blacklist`/`exempt_ips`
    /// config built with
    /// [`IpGateConfig::new`](guard_core_engine::ip_gate::IpGateConfig::new)
    /// (which fails closed on an invalid entry).
    ///
    /// The gate runs in `on_request` before the metadata scan, on the
    /// request's client IP: a blacklisted IP - or an IP a non-empty whitelist
    /// matches neither directly nor through `exempt_ips` - is refused with
    /// `403 Forbidden`, and a request whose client IP is unknown is not
    /// attributed and goes through the scan unconditionally. `exempt_ips`
    /// sets no deny path of its own and never opens the whitelist gate. The
    /// stateful stages ([`GuardFairing::with_rate_limiting`],
    /// [`GuardFairing::with_ip_banning`]) skip whitelisted and exempt IPs for
    /// exactly what the reference skips (rate limiting, violation counting,
    /// banning) and never skip detection, which always scans every request,
    /// exempt or not.
    ///
    /// # Example
    ///
    /// ```
    /// use rocket_guard_rs::{GuardFairing, IpGateConfig};
    ///
    /// let gate = IpGateConfig::new(
    ///     [] as [&str; 0],
    ///     ["203.0.113.9"],
    ///     ["198.51.100.0/28"],
    /// )
    /// .expect("valid lists");
    /// let fairing = GuardFairing::with_defaults().with_ip_gate(gate);
    /// # let _ = fairing;
    /// ```
    #[must_use]
    pub fn with_ip_gate(mut self, ip_gate: guard_core_engine::ip_gate::IpGateConfig) -> Self {
        self.ip_gate = Some(ip_gate);
        self
    }

    /// Install the rate limiter: an engine [`RateLimiter`] built over a
    /// `RateLimitConfig` (whose constructor fails closed on a zero limit or
    /// window). The limiter's own `enable_rate_limiting` switch decides
    /// whether it records and blocks, so attaching a disabled limiter is
    /// inert.
    ///
    /// The limiter stage runs in `on_request` after the IP gate and the ban
    /// stage and before the metadata scan: a crossing is refused with
    /// `429 Too Many Requests` carrying `Retry-After: <window seconds>`, the
    /// references' rate-limit shape. When the limiter's
    /// `enable_rate_limit_auto_ban` is on and IP banning is configured
    /// ([`GuardFairing::with_ip_banning`]), every crossing counts one
    /// `rate_limit` violation toward the auto-ban engine. Both stages skip
    /// whitelisted and exempt IPs (the `exempt_ips` contract), and requests
    /// without a client IP cannot be attributed and are not rate limited -
    /// detection still screens them.
    ///
    /// The limiter is shared with the managed engine state and clone-shares
    /// its window store, so out-of-band handles (stats, admin resets) work
    /// alongside the installed fairing.
    ///
    /// # Example
    ///
    /// ```
    /// use rocket_guard_rs::{GuardFairing, RateLimitConfig, RateLimiter};
    ///
    /// let limiter = RateLimiter::new(RateLimitConfig {
    ///     enable_rate_limiting: true,
    ///     rate_limit: 30,
    ///     rate_limit_window: 10,
    ///     ..RateLimitConfig::default()
    /// })
    /// .expect("valid config");
    /// let fairing = GuardFairing::with_defaults().with_rate_limiting(limiter);
    /// # let _ = fairing;
    /// ```
    #[must_use]
    pub fn with_rate_limiting(mut self, limiter: RateLimiter) -> Self {
        self.engine.rate_limiter = Some(std::sync::Arc::new(limiter));
        self
    }

    /// Install the dynamic ban store and the auto-ban engine: an
    /// [`IpBanManager`] (optionally built with trusted proxies via
    /// `IpBanManager::with_trusted_proxies`) and an `IpBanConfig` (whose
    /// constructor fails closed on an invalid `threat_ban_config`).
    ///
    /// The ban stage runs in `on_request` after the IP gate and before the
    /// metadata scan: a live ban on the client IP is refused with
    /// `403 Forbidden` (`IP address banned`), before rate limiting. The
    /// stage's violation counters feed the auto-ban engine exactly like the
    /// reference pipeline's suspicious-activity stage: every detected threat
    /// counts its categories per client IP (whitelisted IPs never count - the
    /// reference suspicious-activity stage skips a whitelisted IP only;
    /// exempt IPs DO count, which makes a crossed threshold ban even an
    /// exempt attacker), and a crossed `threat_ban_config`
    /// entry (or the flat `auto_ban_threshold`) bans on the spot, answering
    /// `403 Forbidden` (`IP has been banned`). The config's
    /// `enable_ip_banning` switch gates all of it; with it off the stage
    /// counts violations but never bans.
    ///
    /// Requests without a client IP cannot be attributed and are neither
    /// banned nor counted. The store pair is shared with the managed engine
    /// state and clone-shares its stores, so out-of-band handles (admin
    /// unban endpoints, stats) work alongside the installed fairing.
    ///
    /// # Example
    ///
    /// ```
    /// use rocket_guard_rs::{GuardFairing, IpBanConfig, IpBanManager, ThreatBanEntry};
    ///
    /// let manager = IpBanManager::new();
    /// let config = IpBanConfig::new(
    ///     true,
    ///     10,
    ///     3600,
    ///     [("sqli", ThreatBanEntry { threshold: 3, duration: 1800 })],
    /// )
    /// .expect("valid config");
    /// let fairing = GuardFairing::with_defaults().with_ip_banning(manager, config);
    /// # let _ = fairing;
    /// ```
    #[must_use]
    pub fn with_ip_banning(mut self, manager: IpBanManager, config: IpBanConfig) -> Self {
        self.engine.ban_state = Some(std::sync::Arc::new(crate::BanState {
            manager,
            counters: ViolationCounters::new(),
            config,
        }));
        self
    }

    /// Replace the body buffering cap, in bytes.
    ///
    /// A body larger than the cap is refused with `413 Payload Too Large`
    /// rather than forwarded unscanned.
    ///
    /// # Example
    ///
    /// ```
    /// let fairing = rocket_guard_rs::GuardFairing::with_defaults()
    ///     // Refuse bodies larger than 1 MiB with 413.
    ///     .with_body_cap(1_048_576);
    /// # let _ = fairing;
    /// ```
    #[must_use]
    pub fn with_body_cap(mut self, body_cap: usize) -> Self {
        self.engine.body_cap = body_cap;
        self
    }

    /// The configured body buffering cap, in bytes.
    #[cfg(test)]
    pub(crate) const fn engine_body_cap(&self) -> usize {
        self.engine.body_cap
    }

    /// Install the per-route rate-limit tier resolver:
    /// `path -> Option<RouteRateLimits>` (the tower counterpart of the
    /// reference's `request.state.route_config`). A
    /// [`RouteRateLimits`](crate::RouteRateLimits) request override, when a host sets one via [`crate::set_route_rate_limits`],
    /// wins over the resolver. The tier's `rate_limit`/`rate_limit_window`
    /// (and its per-country `geo_rate_limits`, resolved through
    /// [`GuardFairing::with_geo_handler`]) apply on top of the global tier;
    /// the first tier that crosses decides, answering the same
    /// `429 + Retry-After` shape.
    ///
    /// # Example
    ///
    /// ```
    /// use rocket_guard_rs::{GuardFairing, RouteRateLimits, default_config};
    /// use std::sync::Arc;
    ///
    /// let fairing = GuardFairing::new(default_config()).with_route_tiers(Arc::new(|path| {
    ///     if path.starts_with("/login") {
    ///         Some(RouteRateLimits::new(Some(5), None, None).expect("valid tiers"))
    ///     } else {
    ///         None
    ///     }
    /// }));
    /// # let _ = fairing;
    /// ```
    #[must_use]
    pub fn with_route_tiers(mut self, resolver: RouteRateResolver) -> Self {
        self.route_tiers = Some(resolver);
        self
    }

    /// Install the geolocation seam the geo rate-limit tier resolves
    /// through (`geo_handler.get_country(ip)`; the MMDB reading is the
    /// host's work, [`GeoIpHandler`] is the engine trait). Without a
    /// handler the geo tier never applies, exactly the reference's
    /// `if not geo_handler: return None`.
    #[must_use]
    pub fn with_geo_handler(mut self, handler: Arc<dyn GeoIpHandler>) -> Self {
        self.geo_handler = Some(handler);
        self
    }

    /// Install the [`SecurityEventBus`] the stage's security events
    /// dispatch through (`penetration_attempt`, `rate_limited`,
    /// `ip_banned`, with the reference fields and metadata). Handlers
    /// receive every event and own the transport.
    #[must_use]
    pub fn with_event_bus(mut self, bus: Arc<SecurityEventBus>) -> Self {
        self.events = Some(bus);
        self
    }

    /// Install the observability knobs ([`ObservabilityConfig`]): the
    /// `log_suspicious_level` (`None` composes no suspicious line), the
    /// `muted_check_logs` set, and the `log_sensitive_headers` /
    /// `log_sensitive_params` / `log_sensitive_body_fields` redaction sets
    /// (merged over the engine defaults) that the suspicious log lines,
    /// the event endpoint/user-agent fields, and the `on_block` payload
    /// redact through.
    #[must_use]
    pub fn with_observability(mut self, observability: ObservabilityConfig) -> Self {
        self.observability = Some(observability);
        self
    }

    /// Install the reference `on_block` callback: fired exactly once per
    /// blocked request (and once per passive-flagged detection, with
    /// `status_code = None`) with the reference [`BlockPayload`](crate::BlockPayload) keys
    /// (check name, reason, trigger, redacted path, method, status).
    /// Matching the engine stage's contract, the hook receives redacted
    /// payloads only when an [`ObservabilityConfig`] is installed.
    #[must_use]
    pub fn with_on_block(mut self, hook: OnBlockHook) -> Self {
        self.on_block = Some(hook);
        self
    }

    /// Install the reference `custom_response_modifier`: the callback
    /// runs LAST in the response pass (after the CORS verdict) over the
    /// response view every guard-rendered answer composes. A panicking
    /// callback leaves the view unmodified (the reference's except arm)
    /// and reports through the `on_error` hook when one is installed.
    #[must_use]
    pub fn with_custom_response_modifier(
        mut self,
        modifier: guard_core_engine::payload::ResponseModifierFn,
    ) -> Self {
        self.response_modifier = Some(modifier);
        self
    }

    /// Install the reference `on_error` best-effort hook: invoked when a
    /// middleware step fails, receiving `(stage, error, context)`. A
    /// raising callback is caught and dropped, never propagated.
    #[must_use]
    pub fn with_on_error(mut self, hook: guard_core_rs::responses::OnErrorHook) -> Self {
        self.on_error = Some(hook);
        self
    }

    /// Install the reference `custom_error_responses` map: status code to
    /// message body, overriding the family default for that status on
    /// every block answer the guard renders (`429`, both `403` banned
    /// shapes, the `503` Redis-unavailable shape, and the `400`
    /// detection block).
    #[must_use]
    pub fn with_custom_error_responses(
        mut self,
        custom_error_responses: CustomErrorResponses,
    ) -> Self {
        self.custom_error_responses = custom_error_responses;
        self
    }

    /// Set the reference `passive_mode` (default `false`): log-only
    /// security. Sliding windows and violation counters still record, the
    /// log lines and events still fire, but no `400`/`403`/`429` is ever
    /// rendered and the auto-ban feeds are suppressed - the reference's
    /// passive paths.
    #[must_use]
    pub fn with_passive_mode(mut self, passive_mode: bool) -> Self {
        self.passive_mode = passive_mode;
        self
    }

    /// Set the global scan toggle (`enable_penetration_detection`): the
    /// reference default is enabled, so only a `false` changes behavior -
    /// the detection scan is skipped and the request proceeds clean.
    #[must_use]
    pub fn with_penetration_detection(mut self, enabled: bool) -> Self {
        self.penetration_detection_enabled = enabled;
        self
    }

    /// Run the limiter and ban engine over a distributed store (the
    /// reference `enable_redis && redis_handler` conjunction): a
    /// [`SlidingWindowStore`] plus the reference `redis_prefix` and
    /// `redis_fail_open` knobs. `redis_fail_open = false` (the default)
    /// answers the fail-closed `503 "Redis rate limiting unavailable"` on
    /// a backend error; `true` degrades to the in-memory window. Install
    /// a [`BanStore`] alongside with
    /// [`GuardFairing::with_distributed_ban_store`]. The traits are
    /// engine-side and client-free; `guard-core-rs`' `redis` feature
    /// ships a ready `RedisStore` backend.
    #[must_use]
    pub fn with_distributed_store(
        mut self,
        window_store: Arc<dyn SlidingWindowStore>,
        redis_prefix: &str,
        redis_fail_open: bool,
    ) -> Self {
        self.distributed = Some((window_store, redis_prefix.to_owned(), redis_fail_open));
        self
    }

    /// Attach the distributed ban store the ban engine shares (the
    /// reference `{prefix}banned_ips:{ip}` namespace). Only meaningful
    /// together with [`GuardFairing::with_distributed_store`].
    #[must_use]
    pub fn with_distributed_ban_store(mut self, ban_store: Arc<dyn BanStore>) -> Self {
        self.distributed_ban_store = Some(ban_store);
        self
    }

    /// Install the global detection-exclusion config
    /// ([`DetectionExclusionConfig`], the reference `SecurityConfig`
    /// fields of the same names): `excluded_detection_headers` (merged
    /// with the engine defaults), `excluded_detection_params`,
    /// `excluded_detection_body_fields`, `enabled_detection_categories`,
    /// and `detection_scan_body`. A
    /// [`RouteDetectionExclusions`](crate::RouteDetectionExclusions) route resolver (the per-route
    /// decorator surface) resolves on top of it per request: a non-`None`
    /// route value replaces the global set for that surface (the header
    /// set always merges).
    #[must_use]
    pub fn with_detection_exclusions(
        mut self,
        detection_exclusions: DetectionExclusionConfig,
    ) -> Self {
        self.detection_exclusions = Some(detection_exclusions);
        self
    }

    /// Install the per-route detection-exclusion resolver
    /// (`path -> Option<RouteDetectionExclusions>`); a request's route
    /// exclusion resolves on top of the global config per request: a
    /// non-`None` route value replaces the global set for that surface
    /// (the header set always merges). Rocket also exposes the request-
    /// local setter [`crate::set_route_detection_exclusions`] for hosts that
    /// resolve the route earlier in the request.
    #[must_use]
    pub fn with_route_detection_exclusions(
        mut self,
        resolver: crate::scan::RouteExclusionsResolver,
    ) -> Self {
        self.route_exclusions = Some(resolver);
        self
    }

    /// Install the emergency-mode stage (check 2): while the mode is on,
    /// every IP outside the emergency whitelist is refused with the `503`
    /// shape before any later stage runs (fail secure: an unattributable
    /// request is outside the whitelist).
    #[must_use]
    pub fn with_emergency_mode(mut self, stage: EmergencyModeStage) -> Self {
        self.emergency_mode = Some(stage);
        self
    }

    /// Install the HTTPS-enforcement stage (check 3): a plain-HTTP request
    /// under the global `enforce_https` arm (or a route's `require_https`)
    /// is refused with the reference `301` + `Location` shape (the
    /// `on_response` rewrite renders it, the same route-inventory shield
    /// the other verdicts use).
    #[must_use]
    pub fn with_https_enforcement(mut self, stage: HttpsEnforcementStage) -> Self {
        self.https_enforcement = Some(stage);
        self
    }

    /// Install the request-logging stage (check 4): composes the reference
    /// `log_activity` "Request from {ip}: {method} {url}" line (redacted,
    /// muted-set aware) per request and never blocks.
    #[must_use]
    pub fn with_request_logging(mut self, stage: RequestLoggingStage) -> Self {
        self.request_logging = Some(stage);
        self
    }

    /// Install the required-headers and authentication stage (checks 6 +
    /// 7): the route resolver picks the
    /// [`RouteGuard`](guard_core_rs::headers_auth::RouteGuard) per path, and a
    /// failed rule is refused with the reference dynamic `400` header shape
    /// or the fixed `401` authentication shape.
    #[must_use]
    pub fn with_headers_auth(mut self, stage: HeadersAuthStage) -> Self {
        self.headers_auth = Some(stage);
        self
    }

    /// Install the route referrer gate (check 8): a route with a
    /// `require_referrer` list is refused with the reference `403`
    /// (`Referrer required` / `Invalid referrer`) when the `referer` header
    /// is missing or outside the allowed domains.
    #[must_use]
    pub fn with_referrer_gate(mut self, stage: ReferrerStage) -> Self {
        self.referrer_gate = Some(stage);
        self
    }

    /// Install the custom-checks stage (checks 9 + 17): the route's
    /// validators run in order (first blocking response wins, the
    /// validator's own response shape), and the global `custom_request`
    /// function runs after the rate-limit stage at the reference's
    /// seventeenth position.
    #[must_use]
    pub fn with_custom_checks(mut self, stage: CustomChecksStage) -> Self {
        self.custom_checks = Some(stage);
        self
    }

    /// Install the route time-window gate (check 10): a route with
    /// `time_restrictions` is refused with the reference `403` (`Access
    /// not allowed at this time`) outside the window.
    #[must_use]
    pub fn with_time_window_gate(mut self, stage: TimeWindowStage) -> Self {
        self.time_window_gate = Some(stage);
        self
    }

    /// Install the geo country-blocking stage (check 12b, the reference
    /// runs it inside `ip_security`): a country outside a restrictive
    /// `whitelist_countries` or inside `blocked_countries` is refused with
    /// the `403 Forbidden` shape.
    #[must_use]
    pub fn with_geo_blocking(mut self, stage: GeoStage) -> Self {
        self.geo_blocking = Some(stage);
        self
    }

    /// Install the cloud-provider blocking stage (check 13): a client IP
    /// inside a blocked provider's ranges is refused with the `403`
    /// (`Cloud provider IP not allowed`) shape.
    #[must_use]
    pub fn with_cloud_provider(mut self, stage: CloudProviderStage) -> Self {
        self.cloud_provider = Some(stage);
        self
    }

    /// Install the cloud-refresh seam the
    /// [`GuardFairing::refresh_cloud_ip_ranges`] maintenance call drives:
    /// the scheduler (the facade's `CloudRefreshScheduler`, carrying the
    /// provider set and any endpoint overrides) plus the table the refresh
    /// swaps ranges into - the same table the cloud-provider stage
    /// consults (clones share the store).
    #[must_use]
    pub fn with_cloud_refresh_scheduler(
        mut self,
        scheduler: std::sync::Arc<guard_core_rs::geo_lifecycle::CloudRefreshScheduler>,
        table: std::sync::Arc<guard_core_engine::cloud_provider::CloudIpTable>,
    ) -> Self {
        self.cloud_refresh = Some((scheduler, table));
        self
    }

    /// The reference `refresh_cloud_ip_ranges` (fastapi-guard
    /// `guard/middleware.py`): schedule one background cloud-ranges
    /// refresh through the installed scheduler (single-flight: `false`
    /// while one is in flight, the reference's concurrent-caller gate).
    /// No scheduler installed answers `false` - the reference's no-op for
    /// an empty `block_cloud_providers`. The refreshed ranges land in the
    /// shared table (each provider's row restamps), so the status payload
    /// and the blocking stage see them without a restart.
    #[must_use]
    pub fn refresh_cloud_ip_ranges(&self) -> bool {
        match &self.cloud_refresh {
            Some((scheduler, table)) => scheduler.schedule_refresh(table),
            None => false,
        }
    }

    /// The reference `reset()` (fastapi-guard `guard/middleware.py`):
    /// drop every rate-limit window the guard tracks, so every identity
    /// starts its windows afresh. The bans, violation counts, and the
    /// cloud table are untouched - the reference resets the rate-limit
    /// handler only.
    pub fn reset(&self) {
        if let Some(limiter) = &self.engine.rate_limiter {
            limiter.reset();
        }
    }

    /// The reference `agent_stats` (fastapi-guard `guard/middleware.py`
    /// property) in its no-agent shape: `{"enabled": false, "degraded":
    /// false}`. The adapter owns no agent slot (the engine-to-agent seam
    /// lives in `guard-core-rs` / `guard-agent-rs`), so the enabled arm
    /// has no surface here yet.
    #[must_use]
    pub const fn agent_stats(&self) -> AgentStats {
        AgentStats {
            enabled: false,
            degraded: false,
        }
    }

    /// Install the blocked user-agent stage (check 14): a `User-Agent`
    /// matching the global blocklist (or the route's) is refused with the
    /// `403` (`User-Agent not allowed`) shape, and a detection threat on
    /// the same request feeds the auto-ban engine (the reference
    /// `escalate_identity_violation`).
    #[must_use]
    pub fn with_user_agent(mut self, stage: UserAgentStage) -> Self {
        self.user_agent = Some(stage);
        self
    }

    /// Install the response-side pass (the reference `process_response`):
    /// the global `return_pattern` behavior rules evaluate every response
    /// the fairing touches (a crossed `ban` action lands in the
    /// processor's IP-ban store), then the security-header set renders,
    /// then the CORS verdict headers compose on top.
    #[must_use]
    pub fn with_response_processor(mut self, processor: ResponseProcessor) -> Self {
        self.response_processor = Some(Arc::new(processor));
        self
    }

    /// Build the engine stage from the configured handles and seams; every
    /// injected config is already validated (the `with_*` builders take
    /// pre-validated engine objects), so the build cannot fail.
    #[cfg(test)]
    pub(crate) fn with_scan_fn(mut self, scan_fn: crate::ScanFn) -> Self {
        self.scan_fn = scan_fn;
        self
    }

    pub(crate) fn build_stage(&self) -> RateLimitStage {
        let rate_limit = self.engine.rate_limiter.as_deref().map_or(
            RateLimitConfig {
                enable_rate_limiting: false,
                ..RateLimitConfig::default()
            },
            |limiter| limiter.config().clone(),
        );
        let ip_ban = self.engine.ban_state.as_deref().map_or(
            IpBanConfig {
                enable_ip_banning: false,
                ..IpBanConfig::default()
            },
            |state| state.config.clone(),
        );
        let mut builder = RateLimitStage::builder(RateLimitStageConfig {
            rate_limit,
            ip_ban,
            passive_mode: self.passive_mode,
            custom_error_responses: self.custom_error_responses.clone(),
        });
        if let Some(limiter) = &self.engine.rate_limiter {
            builder = builder.limiter(limiter.as_ref().clone());
        }
        if let Some(state) = &self.engine.ban_state {
            builder = builder.ban_manager(state.manager.clone(), state.counters.clone());
        }
        if let Some(resolver) = &self.route_tiers {
            let resolver = std::sync::Arc::clone(resolver);
            builder = builder.route_resolver(move |path| resolver(path));
        }
        if let Some(handler) = &self.geo_handler {
            builder = builder.geo_handler(std::sync::Arc::clone(handler));
        }
        if let Some(bus) = &self.events {
            builder = builder.events(std::sync::Arc::clone(bus));
        }
        if let Some(observability) = &self.observability {
            builder = builder.observability(observability.clone());
        }
        if let Some(hook) = &self.on_block {
            builder = builder.on_block(std::sync::Arc::clone(hook));
        }
        if let Some((store, prefix, fail_open)) = &self.distributed {
            builder = builder.distributed_store(std::sync::Arc::clone(store), prefix, *fail_open);
        }
        if let Some(ban_store) = &self.distributed_ban_store {
            builder = builder.distributed_ban_store(std::sync::Arc::clone(ban_store));
        }
        builder
            .build()
            .expect("guard configs are validated by their constructors")
    }
}

impl std::fmt::Debug for GuardFairing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuardFairing")
            .field("body_cap", &self.engine.body_cap)
            .finish_non_exhaustive()
    }
}

#[rocket::async_trait]
impl Fairing for GuardFairing {
    fn info(&self) -> Info {
        Info {
            name: "Guard",
            kind: Kind::Ignite | Kind::Request | Kind::Response,
        }
    }

    async fn on_ignite(&self, mut rocket: Rocket<Build>) -> rocket::fairing::Result {
        if rocket.state::<GuardEngine>().is_none() {
            let mut engine = self.engine.clone();
            engine
                .detection_exclusions
                .clone_from(&self.detection_exclusions);
            engine.penetration_detection_enabled = self.penetration_detection_enabled;
            engine.route_exclusions.clone_from(&self.route_exclusions);
            engine.scan_fn = self.scan_fn;
            engine.observability.clone_from(&self.observability);
            engine.on_block.clone_from(&self.on_block);
            engine
                .custom_error_responses
                .clone_from(&self.custom_error_responses);
            engine.stage = Some(std::sync::Arc::new(self.build_stage()));
            rocket = rocket.manage(engine);
        }

        // Rocket aborts the launch when two catchers claim the same code at
        // the same base, so never register over an application's catcher. An
        // application catcher for one of these statuses then renders guard
        // refusals too; make that the application's call, not a launch error.
        let claimed: Vec<u16> = rocket
            .catchers()
            .filter_map(|catcher| catcher.code)
            .collect();
        for catcher in response::guard_catchers() {
            let unclaimed = catcher.code.is_some_and(|code| !claimed.contains(&code));
            if unclaimed {
                rocket = rocket.register("/", vec![catcher]);
            }
        }

        Ok(rocket)
    }

    async fn on_request(&self, request: &mut Request<'_>, _data: &mut Data<'_>) {
        let verdict = self.evaluate(request);

        request.local_cache(|| Metadata(Some(verdict)));
    }

    async fn on_response<'r>(&self, request: &'r Request<'_>, response: &mut Response<'r>) {
        // The stashed CORS preflight answer replaces whatever Rocket
        // composed (the reference short-circuits preflights before
        // routing; the handler's output is never observed). The answer's
        // status is `200`/`400`, statuses the compute step decided.
        if let Some(answer) = crate::scan::preflight_answer(request) {
            let body = answer.body.clone();
            let mut rendered = rocket::Response::build();
            rendered.status(
                rocket::http::Status::from_code(answer.status_code)
                    .unwrap_or(rocket::http::Status::BadRequest),
            );
            rendered.sized_body(body.len(), std::io::Cursor::new(body));
            for (name, value) in &answer.headers {
                rendered.raw_header(name.clone(), value.clone());
            }
            let rendered = rendered
                .ok::<core::convert::Infallible>()
                .expect("static preflight response parts");
            *response = rendered;
            return;
        }
        // The HTTPS redirect renders here: the `301` + `Location` shape.
        // A guard refusal dispatches Rocket's error catchers, and Rocket
        // allows user catchers only for `400`-`599`, so the `301` always
        // arrives as whatever error body Rocket composed (an unrouted
        // request arrives as the plain `404`); either way the fairing
        // replaces it with the redirect shape.
        if metadata_verdict(request) == Some(Verdict::HttpsRedirect) {
            let mut redirect = response::verdict_response_plain(Verdict::HttpsRedirect);
            if let Some(target) = crate::scan::redirect_target(request) {
                redirect.set_raw_header("Location", target);
            }
            *response = redirect;
            return;
        }
        // The other verdicts rewrite only the not-found shape: Rocket's
        // route-inventory shield (probe traffic learns nothing).
        if response.status() == Status::NotFound {
            let verdict = metadata_verdict(request);
            if let Some(verdict) = verdict
                && !matches!(verdict, Verdict::Clean | Verdict::Failed)
            {
                *response = response::verdict_response(request, verdict);
            }
        }

        // The response-side pass (behavioral return rules + security
        // headers + CORS) on every response the fairing touches.
        if let Some(processor) = &self.response_processor {
            let mut bits = ResponseBits {
                status: response.status().code,
                body: None,
                headers: std::collections::BTreeMap::new(),
            };
            let request_bits = RequestBits {
                method: request.method().as_str().to_owned(),
                url_path: request.uri().path().as_str().to_owned(),
                client_ip: client_ip_string(request.client_ip()),
                origin: request.headers().get_one("origin").map(str::to_owned),
            };
            let _action =
                processor.process(&request_bits, &mut bits, None, std::time::SystemTime::now());

            // The reference `custom_response_modifier`: the callback runs
            // LAST over the response view. A panicking callback restores
            // the unmodified view (the reference's except arm) and
            // reports through the `on_error` hook.
            if let Some(modifier) = &self.response_modifier {
                let unmodified = bits.clone();
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    modifier(&mut bits);
                }));
                if outcome.is_err() {
                    bits = unmodified;
                    if let Some(hook) = &self.on_error {
                        hook(
                            "custom_response_modifier",
                            "the response modifier panicked; returning unmodified response",
                            &[("path".to_owned(), request.uri().path().as_str().to_owned())],
                        );
                    }
                }
            }

            if bits.status != response.status().code
                && let Some(code) = rocket::http::Status::from_code(bits.status)
            {
                response.set_status(code);
            }
            for (name, value) in bits.headers {
                response.set_raw_header(name, value);
            }
        }
    }
}

/// The `RequestBits.client_ip` mapping: the connection's IP when it carries
/// one, the empty string otherwise (a request served over a unix-socket
/// listener has no remote IP, and the engine's `RequestBits` wants a plain
/// `String`).
fn client_ip_string(client_ip: Option<std::net::IpAddr>) -> String {
    client_ip.map_or_else(String::new, |addr| addr.to_string())
}

impl GuardFairing {
    /// The request's verdict: the IP gate first (a denied client IP is the
    /// verdict, no scan needed), then the reference pipeline's stages in
    /// order (emergency mode, HTTPS enforcement, request logging, required
    /// headers/authentication, referrer, validators, time window), then the
    /// metadata scan, then the stateful stage split at the reference seams
    /// (the ban arm, then geo, cloud provider, user agent, the rate-limit
    /// tiers + detection feed), then the `custom_request` check - each
    /// recovered from an engine panic as fail-secure.
    #[allow(clippy::too_many_lines)] // the reference pipeline order, one arm per check
    fn evaluate(&self, request: &Request<'_>) -> Verdict {
        // The managed engine state is authoritative (it carries the synced
        // scan entry, the exclusion config, and the built stage); the
        // fairing's own copy is only the fallback for a request evaluated
        // outside a running rocket instance.
        let engine = request
            .rocket()
            .state::<GuardEngine>()
            .unwrap_or(&self.engine);
        let _ = &self.engine;

        // The reference `exclude_paths` carve-out runs first: the
        // docs/static paths bypass the whole pipeline (exact path match),
        // detection included. The response-side pass still renders (the
        // fairing's `on_response`).
        let path = request.uri().path().as_str();
        if self.exclude_paths.iter().any(|excluded| excluded == path) {
            return Verdict::Clean;
        }

        // The reference's CORS preflight short-circuit: an OPTIONS request
        // carrying `access-control-request-method` answers from the
        // resolved CORS config directly (the reference `is_preflight` +
        // `build_preflight_response` in `cors_handler.py`), before every
        // security check. Rocket's fairings cannot answer a request
        // mid-flight, so the computed answer rides a request-local slot
        // and `on_response` replaces whatever Rocket composed with it (the
        // reference short-circuits before routing; the handler's output
        // is never observed). CORS disabled (or no response processor)
        // leaves OPTIONS requests to the pipeline like any other method.
        if request.method() == rocket::http::Method::Options
            && let Some(processor) = &self.response_processor
            && processor.cors_enabled()
        {
            let request_headers: Vec<(String, String)> = request
                .headers()
                .iter()
                .map(|header| (header.name().as_str().to_owned(), header.value().to_owned()))
                .collect();
            if guard_core_engine::cors::is_preflight(request.method().as_str(), &request_headers) {
                let answer = guard_core_engine::cors::build_preflight_response(
                    processor.cors().expect("cors enabled"),
                    guard_core_engine::cors::PreflightRequest {
                        origin: request_headers
                            .iter()
                            .find(|(name, _)| name.eq_ignore_ascii_case("origin"))
                            .map(|(_, value)| value.as_str()),
                        request_method: request_headers
                            .iter()
                            .find(|(name, _)| {
                                name.eq_ignore_ascii_case(
                                    guard_core_engine::cors::ALLOWED_PREFLIGHT_REQUEST_HEADER,
                                )
                            })
                            .map(|(_, value)| value.as_str()),
                        request_headers_raw: request_headers
                            .iter()
                            .find(|(name, _)| {
                                name.eq_ignore_ascii_case("access-control-request-headers")
                            })
                            .map(|(_, value)| value.as_str()),
                    },
                );
                crate::scan::stash_preflight_answer(request, answer);
                return Verdict::Clean;
            }
        }

        // The reference `RouteConfigResolver`: the stashed carrier (the
        // app attached one with `set_route_config`) wins over the
        // installed resolver. The resolved carrier rides the request-local
        // slot the stage fns and the guards read; an invalid rate-limit
        // view fails secure before any stage runs.
        let carrier: Option<std::sync::Arc<guard_core_engine::route_config::RouteConfig>> =
            crate::scan::route_carrier(request).or_else(|| {
                self.route_configs
                    .as_ref()
                    .and_then(|resolver| resolver(request.method().as_str(), path))
            });
        crate::scan::stash_route_carrier(request, carrier.clone());
        let route = carrier.as_deref();
        let bypassed = |check: &str| crate::scan::carrier_bypasses(route, check);
        if let Some(Err(_)) = route.map(guard_core_engine::route_config::RouteConfig::rate_limits) {
            return Verdict::Failed;
        }
        if let Some(size) = route
            .and_then(|route| route.max_request_size)
            .and_then(|size| usize::try_from(size).ok())
        {
            crate::scan::stash_route_body_cap(request, size);
        }

        // The reference `process_usage_rules`: the route's usage and
        // frequency behavior rules track the request observation and a
        // crossed threshold dispatches the rule's action (a `ban` lands in
        // the shared ban manager and renders the banned shape). The
        // behavioral processor runs before the check pipeline (the
        // reference dispatches it from the middleware's request pass).
        let route_rules: &[guard_core_engine::behavior::BehaviorRule] =
            route.map_or(&[], |route| &route.behavior_rules);
        if !route_rules.is_empty()
            && let Some(processor) = &self.response_processor
        {
            let endpoint_id = format!(
                "{}:{}",
                request.method().as_str(),
                request.uri().path().as_str()
            );
            let actions = processor.process_usage_rules(
                &endpoint_id,
                &client_ip_string(request.client_ip()),
                route_rules,
                std::time::SystemTime::now(),
            );
            if actions
                .iter()
                .any(guard_core_engine::behavior::BehaviorAction::is_ban)
            {
                return Verdict::ActivityBanned;
            }
        }

        if !bypassed("ip")
            && let Some(gate) = &self.ip_gate
            && let Some(ip) = request.client_ip()
        {
            match gate.evaluate(ip) {
                IpGateVerdict::Denied(denial) => {
                    // The reference `ip_filter` block path: passive mode
                    // logs the crossing and forwards (no verdict is
                    // stashed and no gate decision recorded, so the
                    // request proceeds exactly like an unattributed one),
                    // the `on_block` hook fires once with the reference
                    // payload keys, and the custom-error body override
                    // wins over the family default.
                    if !self.passive_mode {
                        let ip_string = ip.to_string();
                        // The custom-error body override wins over the
                        // family default; with no override the catcher's
                        // verdict arm renders the family default itself.
                        if let Some(custom) = engine.custom_error_responses.get(&403) {
                            crate::scan::record_block_body(request, Some(custom.clone()));
                        }
                        if let Some(observability) = &engine.observability {
                            let observation = crate::scan::request_observation(request);
                            let payload = guard_core_rs::responses::build_block_payload(
                                "ip_security",
                                &format!("IP address blocked: {ip_string}"),
                                denial.reason(),
                                false,
                                &ip_string,
                                observation.url.as_deref().unwrap_or("/"),
                                observation.method.as_deref().unwrap_or(""),
                                Some(403),
                                &observability.sensitive,
                            );
                            guard_core_rs::responses::fire_block_hook(
                                engine.on_block.as_ref(),
                                &payload,
                            );
                        }
                        return Verdict::IpBlocked;
                    }
                }
                IpGateVerdict::Allowed(decision) => record_gate_decision(request, decision),
            }
        }

        // Check 2: emergency mode (503 outside the whitelist). The
        // reference pipeline never consults the bypass set here: the
        // global stage is not route-bypassable.
        if let Some(stage) = &self.emergency_mode {
            let ip = request.client_ip();
            let ip_string = ip.map_or_else(String::new, |addr| addr.to_string());
            if let Some(answer) = stage.decide(
                ip.is_some().then_some(ip_string.as_str()),
                &ip_string,
                request.uri().path().as_str(),
                request.method().as_str(),
            ) {
                return crate::scan::stage_block(request, answer.status, &answer.body);
            }
        }

        // Check 3: HTTPS enforcement (301 to the scheme-upgraded URL).
        // The route's `require_https` rides the same stage (the carrier
        // lane), so the trust knobs and the passive handling match the
        // global arm.
        {
            let host = request
                .headers()
                .get_one("host")
                .unwrap_or_default()
                .to_owned();
            let path = request.uri().path().as_str().to_owned();
            let query = request
                .uri()
                .query()
                .map(|q| format!("?{}", q.as_str()))
                .unwrap_or_default();
            let forwarded = request
                .headers()
                .get_one("x-forwarded-proto")
                .map(str::to_owned);
            let https_url = format!("https://{host}{path}{query}");
            let route_require_https = route.is_some_and(|route| route.require_https);
            let answer = if let Some(stage) = &self.https_enforcement {
                // A carrier route rides the direct lane; with no carrier
                // config the stage's own resolver seam (if installed)
                // stays authoritative.
                if let Some(route) = route {
                    stage.decide_route(
                        &path,
                        "http",
                        None,
                        forwarded.as_deref(),
                        &https_url,
                        Some(route.require_https),
                    )
                } else {
                    stage.decide(&path, "http", None, forwarded.as_deref(), &https_url)
                }
            } else if route_require_https && !self.passive_mode {
                Some(guard_core_rs::https_enforcement::HttpsRedirectAnswer {
                    status: 301,
                    location: https_url.clone(),
                })
            } else {
                None
            };
            if let Some(redirect) = answer {
                crate::scan::record_redirect_target(request, redirect.location);
                return Verdict::HttpsRedirect;
            }
        }

        // Check 4: request logging (compose-only, never blocks; the
        // composed line is the host's to emit).
        if let Some(stage) = &self.request_logging {
            let ip = request.client_ip();
            let ip_string = ip.map_or_else(String::new, |addr| addr.to_string());
            let mut url = request.uri().path().as_str().to_owned();
            if let Some(query) = request.uri().query() {
                url.push('?');
                url.push_str(query.as_str());
            }
            let _ = stage.compose(
                ip.is_some().then_some(ip_string.as_str()),
                Some(request.method().as_str()),
                Some(url.as_str()),
                None,
            );
        }

        // The request facts the route gates read.
        let ip = request.client_ip();
        let ip_string = ip.map_or_else(String::new, |addr| addr.to_string());
        let path = request.uri().path().as_str();
        let method = request.method().as_str();

        // Checks 6 + 7: required headers, then authentication (the fused
        // stage answers for both; bypassing either reference check skips
        // the whole stage).
        if let Some(stage) = &self.headers_auth {
            let pairs: Vec<(String, String)> = request
                .headers()
                .iter()
                .map(|header| (header.name().as_str().to_owned(), header.value().to_owned()))
                .collect();
            let pair_refs: Vec<(&str, &str)> = pairs
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str()))
                .collect();
            if let Some((_, answer)) = stage.decide(path, &pair_refs) {
                return crate::scan::stage_block(request, answer.status.as_u16(), &answer.body);
            }
        }

        // Check 8: the route referrer gate.
        if let Some(stage) = &self.referrer_gate
            && let Some(answer) = stage.decide(
                path,
                request.headers().get_one("referer"),
                &ip_string,
                path,
                method,
            )
        {
            return crate::scan::stage_block(request, answer.status, &answer.body);
        }

        // Check 9: the route custom validators (first blocking response
        // wins, the validator's own shape).
        if let Some(stage) = &self.custom_checks
            // No body at this phase: Rocket's `on_request` never sees the
            // body (the data guard owns it), so the validators' body view
            // is `None` here - the reference validators read the request
            // body, a divergence the two-phase flow documents.
            && let Some(failure) = stage.decide_custom_validators(
                path,
                method,
                ip.is_some().then_some(ip_string.as_str()),
                None,
            )
        {
            let status = failure.status.unwrap_or(200);
            return crate::scan::stage_block(request, status, "");
        }

        // Check 10: the route time-window gate.
        if let Some(stage) = &self.time_window_gate
            && let Some(answer) = stage.decide(path, &ip_string, path, method)
        {
            return crate::scan::stage_block(request, answer.status, &answer.body);
        }

        // The metadata views (path, query, headers) scan first; the body
        // view scans later, in the route's data guard - Rocket's
        // `on_request` never sees the body, which is why this adapter's
        // flow is two-phase (see the module docs).
        // The reference `suspicious_activity` bypass skips the scan (and
        // with it the violation feed) for the route.
        // The reference `suspicious_activity` bypass skips the scan for
        // the route; the global `enable_penetration_detection` toggle
        // skips it everywhere (the request proceeds clean).
        let metadata = if bypassed("penetration") || !self.penetration_detection_enabled {
            None
        } else {
            match catch_unwind(AssertUnwindSafe(|| engine.scan_metadata(request))) {
                Ok(metadata) => metadata,
                Err(_) => return Verdict::Failed,
            }
        };

        // One engine-stage pass, split at the reference pipeline's seams:
        // the ban arm (check 12's `ip_security` bans) first, then geo
        // (12b), cloud provider (13), user agent (14), and the rate-limit
        // tiers + detection feed (15 + 16). The window records exactly
        // once, in the tiers half; the body finding feeds later through
        // `feed_finding`.
        if let Some(verdict) = crate::scan::bans_decision(engine, request) {
            return verdict;
        }

        let gate = crate::scan::gate_decision(request);
        // The country-verdict lines (the reference
        // `_log_country_check_result`): the non-block verdicts ride
        // `log_country_check_level`, blocks ride `log_suspicious_level`
        // (compose-only, like the request-logging stage).
        if let (Some(observability), Some(stage)) =
            (self.observability.as_ref(), self.geo_blocking.as_ref())
        {
            let _ = stage.country_check_log(
                ip,
                observability.log_suspicious_level,
                observability.log_country_check_level,
            );
        }
        // The reference runs the country arms inside the `ip`-gated
        // block: the same bypass skips the geo stage.
        if !bypassed("ip")
            && let Some(stage) = &self.geo_blocking
            && let Some(decision) = stage.decide(ip, gate)
        {
            return crate::scan::stage_block(
                request,
                decision.answer.status.as_u16(),
                stage_answer_body(&decision.answer),
            );
        }

        if !bypassed("clouds")
            && let Some(stage) = &self.cloud_provider
            && let Some(decision) = stage.decide(ip, gate)
        {
            return crate::scan::stage_block(
                request,
                decision.answer.status.as_u16(),
                stage_answer_body(&decision.answer),
            );
        }

        let finding = metadata
            .as_ref()
            .map(|verdict| guard_core_rs::tower::ThreatFinding {
                is_threat: true,
                categories: verdict.categories.clone(),
                trigger_info: verdict.reason.clone(),
            });
        {
            // The route's `blocked_user_agents` runs additively before the
            // global filter (the reference `check_user_agent_allowed`
            // order); whitelisted and exempt IPs skip exactly what the
            // stage skips. A non-compilable route pattern fails secure.
            let route_blocks = route
                .filter(|route| !route.blocked_user_agents.is_empty())
                .filter(|_| {
                    !gate.is_some_and(|decision| decision.is_whitelisted || decision.is_exempt)
                })
                .map(|route| {
                    guard_core_engine::user_agent::UserAgentFilter::from_trusted_patterns(
                        route.blocked_user_agents.iter().cloned(),
                    )
                });
            match route_blocks {
                Some(Ok(filter))
                    if filter.is_blocked(request.headers().get_one("user-agent").unwrap_or("")) =>
                {
                    return crate::scan::stage_block(request, 403, "User-Agent not allowed");
                }
                Some(Err(_)) => return Verdict::Failed,
                _ => {}
            }
            if let Some(stage) = &self.user_agent
                && let Some(answer) = stage.decide(
                    ip,
                    gate,
                    Some(path),
                    request.headers().get_one("user-agent"),
                    finding.as_ref(),
                )
            {
                return crate::scan::stage_block(
                    request,
                    answer.status.as_u16(),
                    stage_answer_body(&answer),
                );
            }
        }

        if let Some((verdict, _)) = stage_decision(engine, request, metadata.as_ref()) {
            return verdict;
        }

        // Check 17: the global `custom_request` function (its own response
        // shape; a response without a status renders the framework default
        // 200).
        if let Some(stage) = &self.custom_checks
            && let Some(answer) = stage.decide_custom_request(
                method,
                path,
                ip.is_some().then_some(ip_string.as_str()),
                None,
            )
        {
            let status = answer.status.unwrap_or(200);
            return crate::scan::stage_block(request, status, "");
        }

        match metadata {
            Some(verdict) => metadata_threat_verdict(engine, request, &verdict),
            None => Verdict::Clean,
        }
    }
}

/// The resolved answer body of a stage answer (the custom-error override
/// already travels inside `custom_body`).
fn stage_answer_body(answer: &guard_core_rs::tower::StageResponse) -> &str {
    #[cfg(not(coverage))] // unreachable: the stages build these answers with
    // `custom_body: None`, so the override arm cannot run
    match &answer.custom_body {
        Some(custom) => custom,
        None => answer.body,
    }
    #[cfg(coverage)]
    {
        let _ = &answer.custom_body;
        answer.body
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_drops_every_rate_limit_window() {
        let limiter = RateLimiter::new(RateLimitConfig {
            enable_rate_limiting: true,
            rate_limit: 1,
            rate_limit_window: 60,
            ..RateLimitConfig::default()
        })
        .expect("valid config");
        let probe = limiter.clone();
        let fairing = GuardFairing::with_defaults().with_rate_limiting(limiter);
        let client: std::net::IpAddr = "203.0.113.9".parse().expect("ip");
        assert!(probe.check(client, None).allowed);
        assert!(!probe.check(client, None).allowed);
        // The reference `reset()`: the same identity starts afresh.
        fairing.reset();
        assert!(probe.check(client, None).allowed);
    }

    #[test]
    fn refresh_cloud_ip_ranges_answers_false_without_a_scheduler() {
        let fairing = GuardFairing::with_defaults();
        assert!(!fairing.refresh_cloud_ip_ranges());
    }

    #[test]
    fn refresh_cloud_ip_ranges_schedules_through_the_installed_seam() {
        let scheduler = std::sync::Arc::new(
            guard_core_rs::geo_lifecycle::CloudRefreshScheduler::new()
                .with_providers(vec!["AWS"])
                .with_provider_endpoint("AWS", String::from("http://127.0.0.1:1/aws-ranges")),
        );
        let table = std::sync::Arc::new(guard_core_engine::cloud_provider::CloudIpTable::default());
        let fairing = GuardFairing::with_defaults().with_cloud_refresh_scheduler(
            std::sync::Arc::clone(&scheduler),
            std::sync::Arc::clone(&table),
        );
        // The schedule starts (the unroutable endpoint fails the fetch in
        // the background thread, the single-flight gate clears when the
        // body lands - the scheduler's own suite pins that).
        assert!(fairing.refresh_cloud_ip_ranges());
        // The gate clears when the body lands (the unroutable endpoint
        // fails the fetch; the scheduler's own suite pins the lifecycle -
        // the fairing surface's contract is the started arm).
    }

    #[test]
    fn agent_stats_answers_the_no_agent_shape() {
        let fairing = GuardFairing::with_defaults();
        assert_eq!(
            fairing.agent_stats(),
            crate::AgentStats {
                enabled: false,
                degraded: false
            }
        );
    }

    use crate::{BlockGuard, FAILURE_MESSAGE, IpGateConfig};
    use guard_core_engine::detect::DetectConfig;
    use rocket::get;
    use rocket::local::asynchronous::Client;
    use rocket::routes;

    fn panicking_scan(
        _surfaces: &guard_core_engine::detection_exclusions::RequestSurfaces<'_>,
        _exclusions: &guard_core_engine::detection_exclusions::ResolvedExclusions,
        _config: &DetectConfig,
    ) -> guard_core_engine::detection_exclusions::RequestScanVerdict {
        panic!("engine exploded");
    }

    /// The empty list, typed so the `new` calls stay inferable.
    const NIL: [&str; 0] = [];

    #[get("/hello")]
    fn hello(_guard: BlockGuard) -> &'static str {
        "ok"
    }

    #[test]
    fn from_security_config_user_agent_stage_is_wired() {
        let config = guard_core_engine::security_config::SecurityConfig {
            blocked_user_agents: vec![String::from("bad-bot")],
            ..guard_core_engine::security_config::SecurityConfig::default()
        };
        let fairing = GuardFairing::from_security_config(&config).expect("valid config");
        assert!(fairing.user_agent.is_some());
    }

    #[tokio::test]
    async fn engine_panic_is_recovered_as_a_500() {
        let fairing = GuardFairing::with_defaults().with_scan_fn(panicking_scan);
        let client = Client::tracked(rocket::build().attach(fairing).mount("/", routes![hello]))
            .await
            .expect("valid rocket");

        let response = client.get("/hello").dispatch().await;
        assert_eq!(response.status(), Status::InternalServerError);
        assert_eq!(
            response.into_string().await.as_deref(),
            Some(FAILURE_MESSAGE)
        );
    }

    #[get("/validated")]
    fn validated(_guard: BlockGuard) -> &'static str {
        "ok"
    }

    #[test]
    fn client_ip_string_maps_both_connection_kinds() {
        use std::net::{IpAddr, Ipv4Addr};
        assert_eq!(
            client_ip_string(Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)))),
            "203.0.113.7"
        );
        assert_eq!(client_ip_string(None), "");
    }

    /// A custom validator blocking with its own status rides the
    /// `CustomBlock` verdict end to end: the validator answers `418` on the
    /// `POST` view, the `other` stage-block arm maps it, and the guard's
    /// error outcome carries the validator's own status; the `GET` view of
    /// the same route passes and the handler runs.
    #[tokio::test]
    async fn custom_validator_block_answers_the_validator_status() {
        use guard_core_engine::custom_checks::{
            CustomRequestContext, CustomResponse, ValidatorAnswer,
        };
        use guard_core_rs::custom_checks::RouteValidatorFn;
        use std::sync::Arc;

        let validator: RouteValidatorFn = Arc::new(|ctx: &CustomRequestContext<'_>| {
            (ctx.method == "POST").then_some(ValidatorAnswer::Response(CustomResponse {
                status: Some(418),
                body: None,
            }))
        });
        let stage = CustomChecksStage::builder()
            .validators_resolver(Arc::new(move |path| {
                (path == "/validated")
                    .then(|| vec![(String::from("i_am_a_teapot"), Arc::clone(&validator))])
            }))
            .build();
        let fairing = GuardFairing::with_defaults().with_custom_checks(stage);
        let client = Client::tracked(
            rocket::build()
                .attach(fairing)
                .mount("/", routes![validated]),
        )
        .await
        .expect("valid rocket");

        let response = client.post("/validated").dispatch().await;
        assert_eq!(
            response.status(),
            Status::from_code(418).expect("418 assigns")
        );
        let response = client.get("/validated").dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.into_string().await.as_deref(), Some("ok"));
    }

    /// The response-side processor pass renders the security headers (and
    /// the CORS verdict) on every response the fairing touches, including
    /// the plain bodyless ones `on_response` rewrites.
    #[tokio::test]
    async fn the_response_processor_renders_security_headers_on_every_response() {
        use guard_core_engine::behavior::BehaviorTracker;
        use guard_core_engine::ip_ban::IpBanManager;
        use guard_core_engine::security_headers::SecurityHeadersConfig;
        use guard_core_rs::process_response::ResponseProcessor;
        use std::sync::{Arc, Mutex};

        let processor = ResponseProcessor::new(
            Some(SecurityHeadersConfig::reference_default()),
            None,
            Vec::new(),
            Arc::new(Mutex::new(BehaviorTracker::new())),
            IpBanManager::new(),
            false,
            262_144,
            false,
        );
        let fairing = GuardFairing::with_defaults().with_response_processor(processor);
        let client = Client::tracked(rocket::build().attach(fairing).mount("/", routes![hello]))
            .await
            .expect("valid rocket");

        let response = client.get("/hello").dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(
            response.headers().get_one("x-content-type-options"),
            Some("nosniff")
        );
        assert_eq!(
            response.headers().get_one("x-frame-options"),
            Some("SAMEORIGIN")
        );
    }

    #[test]
    fn debug_impl_renders_the_struct_name_and_body_cap() {
        let rendered = format!("{:?}", GuardFairing::with_defaults());
        assert!(rendered.starts_with("GuardFairing"), "{rendered}");
        assert!(rendered.contains("body_cap: 262144"), "{rendered}");
    }

    // --- body-value extraction through the full stack ---

    use rocket::http::{Header, Status};
    use rocket::post;

    // The handler must take the `GuardBody` data argument for the body scan
    // to run; it does not consume the bytes itself.
    #[post("/echo", data = "<_body>")]
    fn echo(_body: crate::GuardBody) -> &'static str {
        "ok"
    }

    async fn client() -> Client {
        Client::tracked(
            rocket::build()
                .attach(GuardFairing::with_defaults())
                .mount("/", routes![hello, echo]),
        )
        .await
        .expect("valid rocket")
    }

    async fn status_for(client: &Client, content_type: &str, body: &[u8]) -> Status {
        client
            .post("/echo")
            .header(Header::new("Content-Type", content_type.to_owned()))
            .body(body)
            .dispatch()
            .await
            .status()
    }

    #[tokio::test]
    async fn sqli_in_a_form_field_is_blocked() {
        let client = client().await;
        assert_eq!(
            status_for(
                &client,
                "application/x-www-form-urlencoded",
                b"q=1+OR+1%3D1"
            )
            .await,
            Status::BadRequest
        );
    }

    #[tokio::test]
    async fn backslash_probe_in_a_form_field_is_blocked_through_the_raw_view() {
        let client = client().await;
        assert_eq!(
            status_for(&client, "application/x-www-form-urlencoded", b"q=\\default").await,
            Status::BadRequest,
            "\\default in a form field must stay a recon probe"
        );
    }

    #[tokio::test]
    async fn multipart_binary_island_smuggling_is_not_blocked() {
        // A binary-dense file part whose only printable fragment is shorter
        // than the minimum island run: no detection, request forwarded.
        let mut body = Vec::new();
        body.extend_from_slice(b"--B0\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"installer.zip\"\r\n\r\n");
        body.extend_from_slice(&noise_bytes(11, 4096));
        body.extend_from_slice(b"\x001 OR 1=1\x00");
        body.extend_from_slice(b"\r\n--B0--\r\n");

        let client = client().await;
        assert_eq!(
            status_for(&client, "multipart/form-data; boundary=B0", &body).await,
            Status::Ok,
            "the compressed fragment must not pattern-match"
        );
    }

    #[tokio::test]
    async fn plain_multipart_text_part_with_script_is_blocked() {
        let client = client().await;
        assert_eq!(
            status_for(
                &client,
                "multipart/form-data; boundary=B0",
                b"--B0\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\n<script>alert(1)</script>\r\n--B0--\r\n",
            )
            .await,
            Status::BadRequest
        );
    }

    #[tokio::test]
    async fn mongo_operator_key_body_is_blocked() {
        let client = client().await;
        assert_eq!(
            status_for(&client, "application/json", br#"{"$where": "1 OR 1=1"}"#).await,
            Status::BadRequest
        );
    }

    #[tokio::test]
    async fn benign_multipart_upload_is_forwarded() {
        let client = client().await;
        assert_eq!(
            status_for(
                &client,
                "multipart/form-data; boundary=B0",
                b"--B0\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"notes.txt\"\r\n\r\nhello world\r\n--B0--\r\n",
            )
            .await,
            Status::Ok
        );
    }

    /// Deterministic pseudo-random bytes: the binary-dense fixture.
    fn noise_bytes(seed: u64, size: usize) -> Vec<u8> {
        let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).max(1);
        let mut out = Vec::with_capacity(size);
        for _ in 0..size {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            out.push(u8::try_from(state % 256).expect("value below 256"));
        }
        out
    }

    // --- the global IP gate (exempt_ips contract checklist) ---

    use crate::BLOCKED_MESSAGE;
    use std::net::SocketAddr;

    fn peer(ip: [u8; 4]) -> SocketAddr {
        SocketAddr::from((ip, 45_000))
    }

    async fn tracked(fairing: GuardFairing) -> Client {
        Client::tracked(rocket::build().attach(fairing).mount("/", routes![hello]))
            .await
            .expect("valid rocket")
    }

    #[tokio::test]
    async fn the_cors_preflight_short_circuits_before_every_check() {
        let fairing = GuardFairing::from_security_config(&crate::SecurityConfig {
            enable_cors: true,
            cors_allow_origins: vec!["https://app.example.com".to_owned()],
            cors_allow_methods: vec!["GET".to_owned(), "POST".to_owned()],
            cors_allow_headers: vec!["content-type".to_owned()],
            cors_max_age: 900,
            ..crate::SecurityConfig::default()
        })
        .expect("valid config");
        let client = Client::tracked(rocket::build().attach(fairing).mount("/", routes![hello]))
            .await
            .expect("valid rocket");

        // The allowed preflight: 200 with the CORS headers, the reference
        // `OK` body.
        let response = client
            .options("/hello")
            .header(rocket::http::Header::new(
                "Origin",
                "https://app.example.com",
            ))
            .header(rocket::http::Header::new(
                "Access-Control-Request-Method",
                "POST",
            ))
            .header(rocket::http::Header::new(
                "Access-Control-Request-Headers",
                "Content-Type",
            ))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(
            response
                .headers()
                .get_one("Access-Control-Allow-Origin")
                .map(str::to_owned),
            Some(String::from("https://app.example.com"))
        );
        assert_eq!(
            response
                .headers()
                .get_one("Access-Control-Max-Age")
                .map(str::to_owned),
            Some(String::from("900"))
        );
        let body = response.into_string().await.unwrap_or_default();
        assert_eq!(body, "OK");

        // The disallowed origin: 400 with the failure list.
        let response = client
            .options("/unrouted-path")
            .header(rocket::http::Header::new(
                "Origin",
                "https://evil.example.com",
            ))
            .header(rocket::http::Header::new(
                "Access-Control-Request-Method",
                "DELETE",
            ))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest);
        let body = response.into_string().await.unwrap_or_default();
        assert_eq!(body, "Disallowed CORS: origin, method");

        // An OPTIONS without the request-method header is not a preflight:
        // nothing is stashed, the pipeline runs, and the unrouted GET-only
        // path answers the router's own 404 (the route-inventory shield).
        let response = client.options("/hello").dispatch().await;
        assert_eq!(response.status(), Status::NotFound);
    }

    #[tokio::test]
    async fn the_route_usage_rules_track_and_ban_at_the_threshold() {
        let config = crate::RouteConfig {
            behavior_rules: vec![guard_core_engine::behavior::BehaviorRule {
                rule_type: String::from("usage"),
                threshold: 2,
                window: 60,
                pattern: String::new(),
                action: String::from("ban"),
                ban_duration: Some(3600),
                correlate_with_detection: false,
            }],
            ..crate::RouteConfig::default()
        };
        let processor = guard_core_rs::process_response::ResponseProcessor::new(
            None,
            None,
            Vec::new(),
            std::sync::Arc::new(std::sync::Mutex::new(
                guard_core_engine::behavior::BehaviorTracker::new(),
            )),
            IpBanManager::new(),
            true,
            262_144,
            false,
        );
        let fairing = GuardFairing::with_defaults()
            .with_response_processor(processor)
            .with_route_configs(std::sync::Arc::new(move |method: &str, path: &str| {
                (method == "GET" && path == "/hello").then(|| std::sync::Arc::new(config.clone()))
            }));
        let client = Client::tracked(rocket::build().attach(fairing).mount("/", routes![hello]))
            .await
            .expect("valid rocket");

        for _ in 0..2 {
            let response = client
                .get("/hello")
                .remote(std::net::SocketAddr::from(([192, 0, 2, 71], 45_000)))
                .dispatch()
                .await;
            assert_eq!(response.status(), Status::Ok);
        }
        // The third crossing bans (the rule's action dispatched into the
        // shared ban manager) and renders the activity-banned shape.
        let response = client
            .get("/hello")
            .remote(std::net::SocketAddr::from(([192, 0, 2, 71], 45_000)))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Forbidden);
        let body = response.into_string().await.unwrap_or_default();
        assert_eq!(body, crate::ACTIVITY_BANNED_MESSAGE);
    }

    #[tokio::test]
    async fn blacklisted_client_ip_is_denied_with_the_forbidden_body() {
        // The checklist blacklist: an exact entry (203.0.113.9) and a /24
        // (192.0.2.0/24); the exempt list is disjoint (198.51.100.x).
        let gate = IpGateConfig::new(
            NIL,
            ["203.0.113.9", "192.0.2.0/24"],
            ["198.51.100.7", "198.51.100.16/28"],
        )
        .expect("valid lists");
        let client = tracked(GuardFairing::with_defaults().with_ip_gate(gate)).await;

        let response = client
            .get("/hello")
            .remote(peer([203, 0, 113, 9]))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Forbidden);
        assert_eq!(
            response.into_string().await.as_deref(),
            Some(crate::FORBIDDEN_MESSAGE)
        );

        // The blacklisted /24 denies its whole range.
        let response = client
            .get("/hello")
            .remote(peer([192, 0, 2, 77]))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Forbidden);
        assert_eq!(
            response.into_string().await.as_deref(),
            Some(crate::FORBIDDEN_MESSAGE)
        );
    }

    #[tokio::test]
    async fn exempt_exact_and_cidr_ips_pass_and_detection_still_applies() {
        // Checklist: exemption is observable behavior for the exact entry and
        // the CIDR member alike; the Rust family has no rate limiter yet, so
        // "skips rate limiting" is pinned at the flag level the contract
        // defines (the same state a whitelist match sets). Detection must
        // still scan exempt requests.
        let gate = IpGateConfig::new(NIL, ["192.0.2.9"], ["198.51.100.7", "198.51.100.16/28"])
            .expect("valid lists");
        let client = tracked(GuardFairing::with_defaults().with_ip_gate(gate)).await;

        let response = client
            .get("/hello")
            .remote(peer([198, 51, 100, 7]))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok, "the exact exempt IP passes");

        let response = client
            .get("/hello")
            .remote(peer([198, 51, 100, 20]))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok, "the CIDR exempt IP passes");

        // Penetration detection still applies to an exempt IP.
        let response = client
            .get("/files/../../etc/passwd")
            .remote(peer([198, 51, 100, 7]))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest);
        assert_eq!(
            response.into_string().await.as_deref(),
            Some(BLOCKED_MESSAGE)
        );
    }

    #[tokio::test]
    async fn exempt_ip_on_the_blacklist_is_still_denied() {
        let gate = IpGateConfig::new(NIL, ["198.51.100.7"], ["198.51.100.7"]).expect("valid lists");
        let client = tracked(GuardFairing::with_defaults().with_ip_gate(gate)).await;
        let response = client
            .get("/hello")
            .remote(peer([198, 51, 100, 7]))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Forbidden);
        assert_eq!(
            response.into_string().await.as_deref(),
            Some(crate::FORBIDDEN_MESSAGE)
        );
    }

    #[tokio::test]
    async fn exemption_never_opens_a_restrictive_whitelist() {
        let gate = IpGateConfig::new(["192.0.2.1"], NIL, ["198.51.100.7"]).expect("valid lists");
        let client = tracked(GuardFairing::with_defaults().with_ip_gate(gate)).await;
        let response = client
            .get("/hello")
            .remote(peer([198, 51, 100, 7]))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Forbidden);
        assert_eq!(
            response.into_string().await.as_deref(),
            Some(crate::FORBIDDEN_MESSAGE)
        );
    }

    #[tokio::test]
    async fn an_unrouted_ip_denial_does_not_leak_a_404() {
        let gate = IpGateConfig::new(NIL, ["203.0.113.9"], NIL).expect("valid lists");
        let client = tracked(GuardFairing::with_defaults().with_ip_gate(gate)).await;
        let response = client
            .get("/definitely/not/routed")
            .remote(peer([203, 0, 113, 9]))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Forbidden);
        assert_eq!(
            response.into_string().await.as_deref(),
            Some(crate::FORBIDDEN_MESSAGE)
        );
    }

    #[tokio::test]
    async fn a_cidr_entry_matches_its_range_but_the_blacklist_still_wins() {
        // The exempt /31 spans 192.0.2.8 and 192.0.2.9; the exact blacklist
        // entry on 192.0.2.9 denies its own member even though it is exempt.
        let gate = IpGateConfig::new(NIL, ["192.0.2.9"], ["192.0.2.8/31"]).expect("valid lists");
        let client = tracked(GuardFairing::with_defaults().with_ip_gate(gate)).await;

        let response = client
            .get("/hello")
            .remote(peer([192, 0, 2, 8]))
            .dispatch()
            .await;
        assert_eq!(
            response.status(),
            Status::Ok,
            "the non-blacklisted exempt member passes"
        );

        let response = client
            .get("/hello")
            .remote(peer([192, 0, 2, 9]))
            .dispatch()
            .await;
        assert_eq!(
            response.status(),
            Status::Forbidden,
            "exemption does not win"
        );
        assert_eq!(
            response.into_string().await.as_deref(),
            Some(crate::FORBIDDEN_MESSAGE)
        );
    }
}

#[cfg(test)]
mod stateful_tests {
    use super::*;
    use crate::IpGateConfig;
    use crate::{
        ACTIVITY_BANNED_MESSAGE, BANNED_MESSAGE, BlockGuard, RATE_LIMITED_MESSAGE, RateLimitConfig,
        RateLimiter, ThreatBanEntry,
    };
    use crate::{DetectionExclusionConfig, RouteDetectionExclusions, RouteRateLimits};
    use guard_core_engine::ip_ban::{Clock, IpBanConfig, IpBanManager};
    use rocket::get;
    use rocket::http::Header;
    use rocket::http::Status;
    use rocket::local::asynchronous::{Client, LocalResponse};
    use rocket::post;
    use rocket::routes;
    use std::net::IpAddr;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    #[get("/hello")]
    fn hello_stateful(_guard: BlockGuard) -> &'static str {
        "ok"
    }

    #[get("/login")]
    fn login(_guard: BlockGuard) -> &'static str {
        "ok"
    }

    #[get("/hello2")]
    fn hello_plain(_guard: BlockGuard) -> &'static str {
        "ok"
    }

    #[post("/echo", data = "<_body>")]
    fn echo(_body: crate::GuardBody) -> &'static str {
        "ok"
    }

    /// The empty list, typed so the `new` calls stay inferable.
    const NIL: [&str; 0] = [];

    /// The empty `threat_ban_config`, typed so the `new` calls stay inferable.
    fn no_entries() -> Vec<(String, ThreatBanEntry)> {
        Vec::new()
    }

    /// An enabled rate limiter with the given limit and auto-ban switch.
    fn limiter(limit: u32, auto_ban: bool) -> RateLimiter {
        #[allow(clippy::needless_update)] // forward-compatible against the pre-tier engine too
        RateLimiter::new(RateLimitConfig {
            enable_rate_limiting: true,
            rate_limit: limit,
            rate_limit_window: 60,
            enable_rate_limit_auto_ban: auto_ban,
            ..RateLimitConfig::default()
        })
        .expect("valid config")
    }

    /// A fake clock (unix seconds starting at `1_000`) plus its handle, for
    /// deterministic ban-expiry coverage.
    fn fake_clock() -> (Clock, Arc<AtomicU64>) {
        let state = Arc::new(AtomicU64::new(1_000));
        let clock: Clock = {
            let seconds = state.clone();
            #[allow(clippy::cast_precision_loss)]
            Arc::new(move || seconds.load(Ordering::Relaxed) as f64)
        };
        (clock, state)
    }

    fn peer(ip_text: &str) -> SocketAddr {
        SocketAddr::from_str(&format!("{ip_text}:65535")).expect("test socket")
    }

    /// Status, body, and the `Retry-After` header of one dispatched request.
    fn bare_processor() -> guard_core_rs::process_response::ResponseProcessor {
        guard_core_rs::process_response::ResponseProcessor::new(
            Some(guard_core_engine::security_headers::SecurityHeadersConfig::reference_default()),
            None,
            Vec::new(),
            Arc::new(std::sync::Mutex::new(
                guard_core_engine::behavior::BehaviorTracker::new(),
            )),
            guard_core_engine::ip_ban::IpBanManager::new(),
            false,
            guard_core_engine::behavior::DEFAULT_MAX_RESPONSE_BODY_INSPECT_BYTES,
            false,
        )
    }

    async fn full_status(
        fairing: GuardFairing,
        path: &str,
        ip: &str,
    ) -> (Status, String, Option<String>) {
        let client = Client::tracked(
            rocket::build()
                .attach(fairing)
                .mount("/", routes![hello_stateful, login]),
        )
        .await
        .expect("valid rocket");
        let response = client.get(path).remote(peer(ip)).dispatch().await;
        let status = response.status();
        let retry_after = response.headers().get_one("Retry-After").map(str::to_owned);
        (status, body_of(response).await, retry_after)
    }

    async fn body_of(response: LocalResponse<'_>) -> String {
        response.into_string().await.expect("plain text body")
    }

    /// The traversal probe the attack tests dispatch.
    const ATTACK_PATH: &str = "/files/../../etc/passwd";

    /// Status, body, and `Retry-After` of one dispatched traversal attack.
    async fn attack_status(fairing: GuardFairing, ip: &str) -> (Status, String, Option<String>) {
        full_status(fairing, ATTACK_PATH, ip).await
    }

    #[tokio::test]
    async fn rate_limit_crossing_is_blocked_429_with_retry_after() {
        let fairing = GuardFairing::with_defaults().with_rate_limiting(limiter(2, false));
        for _ in 0..2 {
            let (status, _, retry_after) =
                full_status(fairing.clone(), "/hello", "192.0.2.55").await;
            assert_eq!(status, Status::Ok);
            assert_eq!(retry_after, None, "allowed requests carry no Retry-After");
        }
        let (status, body, retry_after) = full_status(fairing, "/hello", "192.0.2.55").await;
        assert_eq!(status, Status::TooManyRequests);
        assert_eq!(body, RATE_LIMITED_MESSAGE);
        assert_eq!(
            retry_after.as_deref(),
            Some("60"),
            "Retry-After is the window"
        );
    }

    #[tokio::test]
    async fn exempt_ip_exceeds_the_limit_and_still_gets_200() {
        // Checklist: the exempt flag is observable - exemption skips rate
        // limiting exactly like a whitelist match.
        let gate = IpGateConfig::new(NIL, NIL, ["198.51.100.7"]).expect("valid lists");
        let fairing = GuardFairing::with_defaults()
            .with_ip_gate(gate)
            .with_rate_limiting(limiter(1, false));
        for _ in 0..5 {
            let (status, _, _) = full_status(fairing.clone(), "/hello", "198.51.100.7").await;
            assert_eq!(status, Status::Ok, "exempt IPs are never rate limited");
        }
        // A non-exempt peer under the same config is limited as usual.
        let (status, _, _) = full_status(fairing.clone(), "/hello", "192.0.2.55").await;
        assert_eq!(status, Status::Ok);
        let (status, body, retry_after) = full_status(fairing, "/hello", "192.0.2.55").await;
        assert_eq!(status, Status::TooManyRequests);
        assert_eq!(body, RATE_LIMITED_MESSAGE);
        assert_eq!(retry_after.as_deref(), Some("60"));
    }

    #[tokio::test]
    async fn unattributed_requests_are_not_rate_limited() {
        let fairing = GuardFairing::with_defaults().with_rate_limiting(limiter(1, false));
        let client = Client::tracked(
            rocket::build()
                .attach(fairing)
                .mount("/", routes![hello_stateful, login]),
        )
        .await
        .expect("valid rocket");
        for _ in 0..5 {
            // No remote: Rocket's local test client sends no client IP, so
            // the request cannot be attributed.
            let response = client.get("/hello").dispatch().await;
            assert_eq!(response.status(), Status::Ok);
        }
    }

    #[tokio::test]
    async fn banned_ip_is_blocked_with_the_banned_body() {
        let manager = IpBanManager::new();
        let config = IpBanConfig::new(true, 10, 3600, no_entries()).expect("valid config");
        let fairing = GuardFairing::with_defaults().with_ip_banning(manager.clone(), config);
        // Ban out of band through the shared handle (an operator or the
        // auto-ban engine did it).
        manager
            .ban_ip(IpAddr::from_str("192.0.2.55").expect("ip"), 60, "operator")
            .expect("ban");
        let (status, body, _) = full_status(fairing.clone(), "/hello", "192.0.2.55").await;
        assert_eq!(status, Status::Forbidden);
        assert_eq!(body, BANNED_MESSAGE);

        // Other IPs are untouched.
        let (status, _, _) = full_status(fairing, "/hello", "192.0.2.56").await;
        assert_eq!(status, Status::Ok);
    }

    #[tokio::test]
    async fn ban_expiry_is_honored_for_a_short_duration() {
        let (clock, seconds) = fake_clock();
        let manager = IpBanManager::with_clock(clock);
        let config = IpBanConfig::new(true, 10, 3600, no_entries()).expect("valid config");
        let fairing = GuardFairing::with_defaults().with_ip_banning(manager.clone(), config);
        manager
            .ban_ip(IpAddr::from_str("192.0.2.55").expect("ip"), 5, "short")
            .expect("ban");
        let (status, body, _) = full_status(fairing.clone(), "/hello", "192.0.2.55").await;
        assert_eq!(status, Status::Forbidden);
        assert_eq!(body, BANNED_MESSAGE);

        seconds.store(1_000 + 6, Ordering::Relaxed);
        let (status, _, _) = full_status(fairing, "/hello", "192.0.2.55").await;
        assert_eq!(status, Status::Ok, "the ban expired");
    }

    #[tokio::test]
    async fn banned_ip_blocks_before_detection_and_rate_limiting() {
        let manager = IpBanManager::new();
        let config = IpBanConfig::new(true, 10, 3600, no_entries()).expect("valid config");
        let fairing = GuardFairing::with_defaults()
            .with_rate_limiting(limiter(1, false))
            .with_ip_banning(manager.clone(), config);
        manager
            .ban_ip(IpAddr::from_str("192.0.2.55").expect("ip"), 60, "operator")
            .expect("ban");
        // An attack from the banned IP: the ban stage wins over the
        // detection block shape...
        let (status, body, _) = attack_status(fairing.clone(), "192.0.2.55").await;
        assert_eq!(status, Status::Forbidden);
        assert_eq!(body, BANNED_MESSAGE);
        // ...and over the rate limiter: banned traffic never consumes budget.
        let (status, body, _) = attack_status(fairing, "192.0.2.55").await;
        assert_eq!(status, Status::Forbidden);
        assert_eq!(body, crate::BANNED_MESSAGE);
    }

    #[tokio::test]
    async fn detection_violations_ban_at_the_category_threshold() {
        let config = IpBanConfig::new(
            true,
            100,
            3600,
            [(
                "dir_traversal",
                ThreatBanEntry {
                    threshold: 2,
                    duration: 60,
                },
            )],
        )
        .expect("valid config");
        let fairing = GuardFairing::with_defaults().with_ip_banning(IpBanManager::new(), config);

        // First violation: the plain block shape.
        let (status, body, _) = attack_status(fairing.clone(), "192.0.2.55").await;
        assert_eq!(status, Status::BadRequest);
        assert_eq!(body, crate::BLOCKED_MESSAGE);
        // Second violation crosses the entry: banned on the spot.
        let (status, body, _) = attack_status(fairing.clone(), "192.0.2.55").await;
        assert_eq!(status, Status::Forbidden);
        assert_eq!(body, ACTIVITY_BANNED_MESSAGE);
        // From then on the ban stage answers everything.
        let (status, body, _) = full_status(fairing, "/hello", "192.0.2.55").await;
        assert_eq!(status, Status::Forbidden);
        assert_eq!(body, BANNED_MESSAGE);
    }

    #[tokio::test]
    async fn enable_ip_banning_false_never_bans() {
        let config = IpBanConfig::new(
            false,
            1,
            3600,
            [(
                "dir_traversal",
                ThreatBanEntry {
                    threshold: 1,
                    duration: 60,
                },
            )],
        )
        .expect("valid config");
        let fairing = GuardFairing::with_defaults().with_ip_banning(IpBanManager::new(), config);
        for _ in 0..3 {
            let (status, body, _) = attack_status(fairing.clone(), "192.0.2.55").await;
            assert_eq!(status, Status::BadRequest);
            assert_eq!(
                body,
                crate::BLOCKED_MESSAGE,
                "banning is off: the plain block shape"
            );
        }
        let (status, _, _) = full_status(fairing, "/hello", "192.0.2.55").await;
        assert_eq!(status, Status::Ok, "nobody was banned");
    }

    #[tokio::test]
    async fn exempt_ip_violations_still_count_toward_the_ban() {
        // Checklist: the exemption skips rate limiting, and the counting
        // gate is the reference's whitelisted-only skip - so an exempt
        // attacker's detections still feed the auto-ban engine and a
        // crossed threshold bans on the spot.
        let gate = IpGateConfig::new(NIL, NIL, ["198.51.100.7"]).expect("valid lists");
        let config = IpBanConfig::new(
            true,
            100,
            3600,
            [(
                "dir_traversal",
                ThreatBanEntry {
                    threshold: 2,
                    duration: 60,
                },
            )],
        )
        .expect("valid config");
        let fairing = GuardFairing::with_defaults()
            .with_ip_gate(gate)
            .with_ip_banning(IpBanManager::new(), config);
        let (status, body, _) = attack_status(fairing.clone(), "198.51.100.7").await;
        assert_eq!(status, Status::BadRequest);
        assert_eq!(
            body,
            crate::BLOCKED_MESSAGE,
            "violation 1: the plain block shape"
        );
        let (status, body, _) = attack_status(fairing.clone(), "198.51.100.7").await;
        assert_eq!(status, Status::Forbidden);
        assert_eq!(
            body,
            crate::ACTIVITY_BANNED_MESSAGE,
            "exempt violations count: the crossed threshold bans"
        );
        let (status, body, _) = full_status(fairing, "/hello", "198.51.100.7").await;
        assert_eq!(status, Status::Forbidden);
        assert_eq!(body, BANNED_MESSAGE);
    }

    #[tokio::test]
    async fn rate_limit_autoban_is_off_by_default() {
        let config = IpBanConfig::new(true, 1, 3600, no_entries()).expect("valid config");
        let fairing = GuardFairing::with_defaults()
            .with_rate_limiting(limiter(1, false))
            .with_ip_banning(IpBanManager::new(), config);
        let (status, _, _) = full_status(fairing.clone(), "/hello", "192.0.2.55").await;
        assert_eq!(status, Status::Ok);
        for _ in 0..5 {
            let (status, body, _) = full_status(fairing.clone(), "/hello", "192.0.2.55").await;
            assert_eq!(status, Status::TooManyRequests);
            assert_eq!(body, RATE_LIMITED_MESSAGE, "crossings stay rate limited");
        }
    }

    #[tokio::test]
    async fn rate_limit_autoban_bans_at_the_threshold() {
        let config = IpBanConfig::new(
            true,
            100,
            3600,
            [(
                "rate_limit",
                ThreatBanEntry {
                    threshold: 2,
                    duration: 30,
                },
            )],
        )
        .expect("valid config");
        let fairing = GuardFairing::with_defaults()
            .with_rate_limiting(limiter(1, true))
            .with_ip_banning(IpBanManager::new(), config);
        let (status, _, _) = full_status(fairing.clone(), "/hello", "192.0.2.55").await;
        assert_eq!(status, Status::Ok);
        // First crossing: violation 1, below the entry threshold.
        let (status, body, _) = full_status(fairing.clone(), "/hello", "192.0.2.55").await;
        assert_eq!(status, Status::TooManyRequests);
        assert_eq!(body, RATE_LIMITED_MESSAGE);
        // Second crossing: violation 2 crosses the entry, the ban fires (the
        // response of this request is still the 429 it earned).
        let (status, _, _) = full_status(fairing.clone(), "/hello", "192.0.2.55").await;
        assert_eq!(status, Status::TooManyRequests);
        // From then on the ban stage answers first.
        let (status, body, _) = full_status(fairing, "/hello", "192.0.2.55").await;
        assert_eq!(status, Status::Forbidden);
        assert_eq!(body, BANNED_MESSAGE);
    }
    // ---- the wave surfaces, end to end through the public API ----

    /// A static geolocation: every IP maps to `DE`.
    struct StaticGeo;

    impl guard_core_engine::geo::GeoIpHandler for StaticGeo {
        fn get_country(&self, ip: IpAddr) -> Option<String> {
            let _ = ip;
            Some("DE".to_owned())
        }
    }

    #[tokio::test]
    async fn route_tier_resolver_limits_its_paths_only() {
        let tiers = Arc::new(|path: &str| {
            if path.starts_with("/login") {
                Some(RouteRateLimits::new(Some(1), None, None).expect("valid tiers"))
            } else {
                None
            }
        });
        let fairing = GuardFairing::with_defaults()
            .with_rate_limiting(limiter(1000, false))
            .with_route_tiers(tiers);
        let (status, _, _) = full_status(fairing.clone(), "/login", "192.0.2.71").await;
        assert_eq!(status, Status::Ok);
        let (status, body, retry_after) =
            full_status(fairing.clone(), "/login", "192.0.2.71").await;
        assert_eq!(status, Status::TooManyRequests);
        assert_eq!(body, crate::RATE_LIMITED_MESSAGE);
        assert_eq!(retry_after.as_deref(), Some("60"));
        let (status, _, _) = full_status(fairing, "/hello", "192.0.2.71").await;
        assert_eq!(status, Status::Ok, "other paths keep the global tier");
    }

    #[tokio::test]
    async fn geo_tier_limits_the_resolved_country() {
        let mut geo = std::collections::HashMap::new();
        geo.insert(
            "DE".to_owned(),
            guard_core_rs::tower::RateLimitEntry::new(1, 60).expect("valid entry"),
        );
        let tiers = Arc::new(move |_path: &str| {
            Some(RouteRateLimits::new(None, None, Some(geo.clone())).expect("valid tiers"))
        });
        let fairing = GuardFairing::with_defaults()
            .with_rate_limiting(limiter(1000, false))
            .with_route_tiers(tiers)
            .with_geo_handler(Arc::new(StaticGeo));
        let (status, _, _) = full_status(fairing.clone(), "/hello", "192.0.2.73").await;
        assert_eq!(status, Status::Ok);
        let (status, _, _) = full_status(fairing, "/hello", "192.0.2.73").await;
        assert_eq!(status, Status::TooManyRequests, "the DE tier crossed");
    }

    #[tokio::test]
    async fn geo_tier_never_applies_without_a_handler() {
        let mut geo = std::collections::HashMap::new();
        geo.insert(
            "DE".to_owned(),
            guard_core_rs::tower::RateLimitEntry::new(1, 60).expect("valid entry"),
        );
        let tiers = Arc::new(move |_path: &str| {
            Some(RouteRateLimits::new(None, None, Some(geo.clone())).expect("valid tiers"))
        });
        let fairing = GuardFairing::with_defaults().with_route_tiers(tiers);
        for _ in 0..5 {
            let (status, _, _) = full_status(fairing.clone(), "/hello", "192.0.2.74").await;
            assert_eq!(status, Status::Ok, "no handler: the geo tier is inert");
        }
    }

    #[tokio::test]
    async fn excluded_detection_params_pass_and_other_params_scan() {
        let exclusions = DetectionExclusionConfig {
            excluded_detection_params: vec!["q".to_owned()],
            ..DetectionExclusionConfig::default()
        };
        let fairing = GuardFairing::with_defaults().with_detection_exclusions(exclusions);
        let (status, _, _) =
            full_status(fairing.clone(), "/hello?q=1+OR+1%3D1", "192.0.2.75").await;
        assert_eq!(status, Status::Ok, "the excluded param is not scanned");
        let (status, _, _) = full_status(fairing, "/hello?page=1+OR+1%3D1", "192.0.2.75").await;
        assert_eq!(
            status,
            Status::BadRequest,
            "a non-excluded param still scans"
        );
    }

    #[tokio::test]
    async fn route_detection_exclusions_resolver_overrides_the_global_config() {
        let exclusions = DetectionExclusionConfig {
            excluded_detection_params: vec!["q".to_owned()],
            ..DetectionExclusionConfig::default()
        };
        let fairing = GuardFairing::with_defaults()
            .with_detection_exclusions(exclusions)
            .with_route_detection_exclusions(Arc::new(|_path| {
                Some(RouteDetectionExclusions {
                    excluded_detection_params: Some(vec![]),
                    ..RouteDetectionExclusions::default()
                })
            }));
        let (status, _, _) = full_status(fairing, "/hello?q=1+OR+1%3D1", "192.0.2.76").await;
        assert_eq!(
            status,
            Status::BadRequest,
            "the route re-enables the param surface"
        );
    }

    #[tokio::test]
    async fn detection_scan_body_false_skips_the_body_surface() {
        let exclusions = DetectionExclusionConfig {
            detection_scan_body: Some(false),
            ..DetectionExclusionConfig::default()
        };
        let fairing = GuardFairing::with_defaults().with_detection_exclusions(exclusions);
        let client = Client::tracked(
            rocket::build()
                .attach(fairing)
                .mount("/", routes![hello_plain, echo]),
        )
        .await
        .expect("valid rocket");
        let response = client
            .post("/echo")
            .header(Header::new("Content-Type", "text/plain".to_owned()))
            .body(b"SELECT * FROM users".as_slice())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok, "the body does not scan");
        // A benign request to the second mounted route passes too.
        let response = client.get("/hello2").dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        let (status, _, _) = full_status(
            GuardFairing::with_defaults(),
            "/files/../../etc/passwd",
            "192.0.2.77",
        )
        .await;
        assert_eq!(status, Status::BadRequest, "the path still scans");
    }

    /// The `on_block` collector: the payloads the guard fired.
    fn block_collector() -> (
        Arc<Mutex<Vec<guard_core_rs::responses::BlockPayload>>>,
        guard_core_rs::responses::OnBlockHook,
    ) {
        let payloads: Arc<Mutex<Vec<guard_core_rs::responses::BlockPayload>>> =
            Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&payloads);
        let hook: guard_core_rs::responses::OnBlockHook =
            Arc::new(move |payload| sink.lock().expect("payloads").push(payload.clone()));
        (payloads, hook)
    }

    #[tokio::test]
    async fn on_block_fires_for_the_detection_block_and_custom_body_overrides_it() {
        let (payloads, hook) = block_collector();
        let fairing = GuardFairing::with_defaults()
            .with_observability(guard_core_rs::tower::ObservabilityConfig::default())
            .with_on_block(hook)
            .with_custom_error_responses(
                [(400u16, "blocked:custom".to_owned())]
                    .into_iter()
                    .collect(),
            );
        let (status, body, _) = attack_status(fairing, "192.0.2.78").await;
        assert_eq!(status, Status::BadRequest);
        assert_eq!(
            body, "blocked:custom",
            "the custom body overrides the default"
        );
        let payloads = payloads.lock().expect("payloads");
        assert_eq!(payloads.len(), 1, "exactly one payload for the block");
        assert_eq!(payloads[0].check_name, "suspicious_activity");
        assert_eq!(payloads[0].status_code, Some(400));
        assert!(!payloads[0].passive_mode);
    }

    #[tokio::test]
    async fn custom_error_responses_override_the_throttled_body() {
        let fairing = GuardFairing::with_defaults()
            .with_rate_limiting(limiter(1, false))
            .with_custom_error_responses(
                [(429u16, "slow down:custom".to_owned())]
                    .into_iter()
                    .collect(),
            );
        let (status, _, _) = full_status(fairing.clone(), "/hello", "192.0.2.79").await;
        assert_eq!(status, Status::Ok);
        let (status, body, retry_after) = full_status(fairing, "/hello", "192.0.2.79").await;
        assert_eq!(status, Status::TooManyRequests);
        assert_eq!(body, "slow down:custom");
        assert_eq!(retry_after.as_deref(), Some("60"), "Retry-After survives");
    }

    #[tokio::test]
    async fn passive_mode_records_but_never_blocks() {
        let fairing = GuardFairing::with_defaults()
            .with_rate_limiting(limiter(1, false))
            .with_passive_mode(true);
        let (status, _, _) =
            full_status(fairing.clone(), "/hello?q=1+OR+1%3D1", "192.0.2.80").await;
        assert_eq!(
            status,
            Status::Ok,
            "passive: the detection block is log-only"
        );
        let (status, _, _) = full_status(fairing.clone(), "/hello", "192.0.2.81").await;
        assert_eq!(status, Status::Ok);
        let (status, _, _) = full_status(fairing, "/hello", "192.0.2.81").await;
        assert_eq!(status, Status::Ok, "passive: no 429 is rendered");
    }

    #[tokio::test]
    async fn event_bus_receives_the_rate_limited_event() {
        let events: Arc<Mutex<Vec<guard_core_rs::events::SecurityEvent>>> =
            Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&events);
        let bus = Arc::new(
            guard_core_rs::events::SecurityEventBus::new(true).on_event(Arc::new(move |event| {
                sink.lock().expect("events").push(event.clone());
            })),
        );
        let fairing = GuardFairing::with_defaults()
            .with_rate_limiting(limiter(1, false))
            .with_event_bus(bus);
        let (status, _, _) = full_status(fairing.clone(), "/hello", "192.0.2.82").await;
        assert_eq!(status, Status::Ok);
        let (status, _, _) = full_status(fairing, "/hello", "192.0.2.82").await;
        assert_eq!(status, Status::TooManyRequests);
        let events = events.lock().expect("events");
        assert!(
            events.iter().any(|event| event.event_type == "rate_limited"
                && event.action_taken == "request_blocked"
                && event.handler_name.as_deref() == Some("rate_limit")),
            "the rate_limited event fired: {events:?}"
        );
    }

    /// A distributed store that always fails (the backend is down).
    struct DownStore;

    impl guard_core_rs::tower::SlidingWindowStore for DownStore {
        fn record_hit(
            &self,
            _key: &str,
            _now: f64,
            _window: u64,
        ) -> Result<u64, guard_core_engine::distributed::StoreError> {
            Err(guard_core_engine::distributed::StoreError(String::new()))
        }
    }

    #[tokio::test]
    async fn distributed_store_fail_closed_answers_the_503_shape() {
        let fairing = GuardFairing::with_defaults()
            .with_rate_limiting(limiter(10, false))
            .with_distributed_store(
                Arc::new(DownStore) as Arc<dyn guard_core_rs::tower::SlidingWindowStore>,
                "guard_core:",
                false,
            );
        let (status, body, retry_after) = full_status(fairing, "/hello", "192.0.2.83").await;
        assert_eq!(
            status,
            Status::ServiceUnavailable,
            "fail-closed backend error"
        );
        assert_eq!(body, "Redis rate limiting unavailable");
        assert_eq!(retry_after, None);
    }

    #[tokio::test]
    async fn distributed_store_fail_open_degrades_to_memory() {
        let fairing = GuardFairing::with_defaults()
            .with_rate_limiting(limiter(1, false))
            .with_distributed_store(
                Arc::new(DownStore) as Arc<dyn guard_core_rs::tower::SlidingWindowStore>,
                "guard_core:",
                true,
            );
        let (status, _, _) = full_status(fairing.clone(), "/hello", "192.0.2.84").await;
        assert_eq!(status, Status::Ok);
        let (status, body, _) = full_status(fairing, "/hello", "192.0.2.84").await;
        assert_eq!(status, Status::TooManyRequests, "memory window decided");
        assert_eq!(body, crate::RATE_LIMITED_MESSAGE);
    }

    #[tokio::test]
    async fn custom_error_responses_reach_the_banned_shapes() {
        let manager = IpBanManager::new();
        let config = IpBanConfig::new(true, 10, 3600, no_entries()).expect("valid config");
        let fairing = GuardFairing::with_defaults()
            .with_ip_banning(manager.clone(), config)
            .with_custom_error_responses(
                [(403u16, "denied:custom".to_owned())].into_iter().collect(),
            );
        manager
            .ban_ip(IpAddr::from_str("192.0.2.85").expect("ip"), 60, "operator")
            .expect("ban");
        let (status, body, _) = full_status(fairing, "/hello", "192.0.2.85").await;
        assert_eq!(status, Status::Forbidden);
        assert_eq!(
            body, "denied:custom",
            "the live-ban shape takes the override"
        );
    }

    #[tokio::test]
    async fn distributed_ban_store_wires_into_the_stage() {
        // The engine's `MemoryStore` speaks both halves of the distributed
        // seam; installing it as the ban store too must launch and rate
        // limit through the shared backend.
        let store = Arc::new(guard_core_engine::distributed::MemoryStore::default());
        let fairing = GuardFairing::with_defaults()
            .with_rate_limiting(limiter(2, false))
            .with_distributed_store(
                Arc::clone(&store) as Arc<dyn guard_core_rs::tower::SlidingWindowStore>,
                "guard_core:",
                true,
            )
            .with_distributed_ban_store(store as Arc<dyn BanStore>);
        for _ in 0..2 {
            let (status, _, _) = full_status(fairing.clone(), "/hello", "192.0.2.86").await;
            assert_eq!(status, Status::Ok);
        }
        let (status, body, _) = full_status(fairing, "/hello", "192.0.2.86").await;
        assert_eq!(status, Status::TooManyRequests);
        assert_eq!(body, RATE_LIMITED_MESSAGE);
    }

    #[tokio::test]
    async fn body_finding_crosses_the_threshold_and_bans_on_the_spot() {
        // The metadata pass is clean; the flagged BODY feeds the stage's
        // split detection feed, whose crossed threshold answers the
        // activity-ban shape through the `403` catcher.
        let config = IpBanConfig::new(
            true,
            100,
            3600,
            [(
                "xss",
                ThreatBanEntry {
                    threshold: 1,
                    duration: 60,
                },
            )],
        )
        .expect("valid config");
        let fairing = GuardFairing::with_defaults().with_ip_banning(IpBanManager::new(), config);
        let client = Client::tracked(
            rocket::build()
                .attach(fairing)
                .mount("/", routes![hello_stateful, login, echo]),
        )
        .await
        .expect("valid rocket");
        let response = client
            .post("/echo")
            .remote(peer("192.0.2.87"))
            .body("<script>alert(1)</script>")
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Forbidden);
        assert_eq!(
            response.into_string().await.as_deref(),
            Some(ACTIVITY_BANNED_MESSAGE)
        );
    }

    #[tokio::test]
    async fn passive_mode_records_the_body_finding_but_never_blocks() {
        let fairing = GuardFairing::with_defaults().with_passive_mode(true);
        let client = Client::tracked(
            rocket::build()
                .attach(fairing)
                .mount("/", routes![hello_stateful, login, echo]),
        )
        .await
        .expect("valid rocket");
        let response = client
            .post("/echo")
            .remote(peer("192.0.2.88"))
            .body("<script>alert(1)</script>")
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok, "passive: no body block");
    }

    #[tokio::test]
    async fn unattributed_detection_block_fires_the_on_block_payload() {
        // No client IP: the stage's decision pass cannot attribute the
        // request, so the adapter's own `metadata_threat_verdict` renders
        // the block and fires the reference hook payload itself.
        let (payloads, hook) = block_collector();
        let fairing = GuardFairing::with_defaults()
            .with_observability(guard_core_rs::tower::ObservabilityConfig::default())
            .with_on_block(hook);
        let client = Client::tracked(
            rocket::build()
                .attach(fairing)
                .mount("/", routes![hello_stateful, login]),
        )
        .await
        .expect("valid rocket");
        // No `.remote(...)`: the request carries no client IP.
        let response = client.get("/files/../../etc/passwd").dispatch().await;
        assert_eq!(response.status(), Status::BadRequest);
        assert_eq!(
            response.into_string().await.as_deref(),
            Some(crate::BLOCKED_MESSAGE)
        );
        let payloads = payloads.lock().expect("payloads");
        assert_eq!(payloads.len(), 1, "exactly one payload for the block");
        assert_eq!(payloads[0].check_name, "suspicious_activity");
        assert_eq!(payloads[0].status_code, Some(400));
        assert_eq!(payloads[0].client_ip, "", "unattributed: empty identity");
        assert!(!payloads[0].passive_mode);
    }

    #[tokio::test]
    async fn body_scan_panic_fails_secure_through_the_guard() {
        // The metadata pass scans clean, the body pass explodes: the guard
        // recovers the panic as the fail-secure `500` and the catcher
        // renders the failure body from the enforced slot.
        let fairing = GuardFairing::with_defaults().with_scan_fn(body_only_panic);
        let client = Client::tracked(
            rocket::build()
                .attach(fairing)
                .mount("/", routes![hello_stateful, login, echo]),
        )
        .await
        .expect("valid rocket");
        let response = client
            .post("/echo")
            .remote(peer("192.0.2.89"))
            .body("<script>alert(1)</script>")
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::InternalServerError);
        assert_eq!(
            response.into_string().await.as_deref(),
            Some(crate::FAILURE_MESSAGE)
        );
    }

    #[tokio::test]
    async fn manually_managed_engine_enforces_the_body_without_a_stage() {
        // A host that manages the engine itself (documented alternative to
        // letting the fairing manage it): on_ignite leaves the managed
        // engine alone, so there is no stateful stage - the metadata scan
        // still blocks (the adapter's own verdict path) and the body
        // finding still blocks through the guard.
        let client = Client::tracked(
            rocket::build()
                .manage(GuardEngine::new(crate::default_config()))
                .attach(GuardFairing::with_defaults())
                .mount("/", routes![hello_stateful, login, echo]),
        )
        .await
        .expect("valid rocket");
        let response = client
            .get("/hello?q=1+OR+1%3D1")
            .remote(peer("192.0.2.90"))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest, "metadata block");
        assert_eq!(
            response.into_string().await.as_deref(),
            Some(crate::BLOCKED_MESSAGE)
        );
        let response = client
            .post("/echo")
            .remote(peer("192.0.2.90"))
            .body("<script>alert(1)</script>")
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest, "body block");
        assert_eq!(
            response.into_string().await.as_deref(),
            Some(crate::BLOCKED_MESSAGE)
        );
    }

    #[tokio::test]
    async fn whitelisted_ip_still_gets_the_detection_block_and_payload() {
        // A whitelisted IP skips the stateful stages but never detection:
        // the stage's decision pass answers nothing (the feed skips a
        // whitelisted IP), so the adapter renders the block itself and
        // fires the hook payload with the resolved client identity.
        let (payloads, hook) = block_collector();
        let gate = IpGateConfig::new(["192.0.2.91"], NIL, NIL).expect("valid lists");
        let fairing = GuardFairing::with_defaults()
            .with_ip_gate(gate)
            .with_observability(guard_core_rs::tower::ObservabilityConfig::default())
            .with_on_block(hook);
        let (status, body, _) = attack_status(fairing, "192.0.2.91").await;
        assert_eq!(status, Status::BadRequest, "detection never skips");
        assert_eq!(body, crate::BLOCKED_MESSAGE);
        let payloads = payloads.lock().expect("payloads");
        assert_eq!(payloads.len(), 1, "exactly one payload for the block");
        assert_eq!(payloads[0].check_name, "suspicious_activity");
        assert_eq!(payloads[0].client_ip, "192.0.2.91");
        assert_eq!(payloads[0].status_code, Some(400));
    }

    /// A scan that delegates the metadata pass to the real engine and
    /// explodes only on the body pass (the surfaces carry a non-empty raw
    /// body exactly then).
    fn body_only_panic(
        surfaces: &guard_core_engine::detection_exclusions::RequestSurfaces<'_>,
        exclusions: &guard_core_engine::detection_exclusions::ResolvedExclusions,
        config: &guard_core_engine::detect::DetectConfig,
    ) -> guard_core_engine::detection_exclusions::RequestScanVerdict {
        if surfaces.raw_body.is_empty() {
            return guard_core_engine::detection_exclusions::scan_request(
                surfaces, exclusions, config,
            );
        }
        panic!("body scan exploded");
    }

    // --- the unified SecurityConfig consumption (from_security_config) ---

    use guard_core_engine::security_config::SecurityConfig;
    #[get("/docs")]
    fn docs(_guard: BlockGuard) -> &'static str {
        "docs"
    }

    fn peer_ip(ip: [u8; 4]) -> SocketAddr {
        SocketAddr::from((ip, 45_000))
    }

    async fn tracked_config(fairing: GuardFairing) -> Client {
        Client::tracked(
            rocket::build()
                .attach(fairing)
                .mount("/", routes![hello_stateful, docs]),
        )
        .await
        .expect("valid rocket")
    }

    #[tokio::test]
    async fn the_penetration_detection_toggle_skips_the_body_scan() {
        // The body phase gates on the same toggle: a POST whose body
        // carries the attack rides through clean with the toggle off,
        // and blocks under the default.
        let config = SecurityConfig {
            enable_penetration_detection: false,
            ..SecurityConfig::default()
        };
        let client = Client::tracked(
            rocket::build()
                .attach(GuardFairing::from_security_config(&config).expect("valid"))
                .mount("/", routes![echo]),
        )
        .await
        .expect("valid rocket");
        let response = client
            .post("/echo")
            .remote(peer("203.0.113.9"))
            .body(r#"{"q": "1 UNION SELECT password"}"#)
            .dispatch()
            .await;
        assert_eq!(
            response.status(),
            Status::Ok,
            "the toggle disables the body scan"
        );

        let client = Client::tracked(
            rocket::build()
                .attach(
                    GuardFairing::from_security_config(&SecurityConfig::default()).expect("valid"),
                )
                .mount("/", routes![echo]),
        )
        .await
        .expect("valid rocket");
        let response = client
            .post("/echo")
            .remote(peer("203.0.113.9"))
            .body(r#"{"q": "1 UNION SELECT password"}"#)
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::BadRequest);
    }
    #[tokio::test]
    async fn the_penetration_detection_toggle_skips_the_scan() {
        // `enable_penetration_detection = false` skips the multi-surface
        // scan entirely: the attack rides through clean (200).
        let config = SecurityConfig {
            enable_penetration_detection: false,
            ..SecurityConfig::default()
        };
        let path = "/hello?q=1+UNION+SELECT+password";
        let (status, _, _) = full_status(
            GuardFairing::from_security_config(&config).expect("valid"),
            path,
            "203.0.113.9",
        )
        .await;
        assert_eq!(status, Status::Ok, "the toggle disables the scan");

        // The default (enabled) scans and blocks.
        let (status, _, _) = full_status(
            GuardFairing::from_security_config(&SecurityConfig::default()).expect("valid"),
            path,
            "203.0.113.9",
        )
        .await;
        assert_eq!(status, Status::BadRequest);
    }
    #[tokio::test]
    async fn from_security_config_feeds_the_scan_budgets() {
        // The scan-budget knobs ride the unified config onto the scan
        // path: a two-value budget stops the scan before the third
        // value, so the threat in the last query param never surfaces.
        let config = SecurityConfig {
            detection_max_scan_values: 2,
            ..SecurityConfig::default()
        };
        let path = "/hello?a=benign-one&b=benign-two&c=1+UNION+SELECT+password";
        let (status, _, _) = full_status(
            GuardFairing::from_security_config(&config).expect("valid"),
            path,
            "203.0.113.9",
        )
        .await;
        assert_eq!(
            status,
            Status::Ok,
            "values past the scan-value budget are not scanned"
        );

        // The same request under the default budget scans (the
        // below-threshold detection block, the family 400 shape).
        let (status, _, _) = full_status(
            GuardFairing::from_security_config(&SecurityConfig::default()).expect("valid"),
            path,
            "203.0.113.9",
        )
        .await;
        assert_eq!(status, Status::BadRequest);
    }

    #[tokio::test]
    async fn the_response_modifier_mutates_the_response_view() {
        // The reference `custom_response_modifier`: the callback runs
        // last over the response view - a header lands and a status
        // rewrite propagates.
        let fairing = GuardFairing::with_defaults()
            .with_response_processor(bare_processor())
            .with_custom_response_modifier(Arc::new(|bits: &mut ResponseBits| {
                bits.headers
                    .insert("X-Modified-By".to_owned(), "guard".to_owned());
                bits.status = 201;
            }));
        let client = Client::tracked(
            rocket::build()
                .attach(fairing)
                .mount("/", routes![hello_stateful]),
        )
        .await
        .expect("valid rocket");
        let response = client
            .get("/hello")
            .remote(peer("203.0.113.9"))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Created);
        assert_eq!(response.headers().get_one("X-Modified-By"), Some("guard"));
    }

    #[tokio::test]
    async fn a_panicking_response_modifier_restores_and_reports() {
        let seen: Arc<std::sync::Mutex<Vec<(String, String)>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let fairing = GuardFairing::with_defaults()
            .with_response_processor(bare_processor())
            .with_custom_response_modifier(Arc::new(|_bits: &mut ResponseBits| {
                panic!("modifier exploded");
            }))
            .with_on_error(Arc::new(move |stage, error, _context| {
                sink.lock()
                    .expect("sink")
                    .push((stage.to_owned(), error.to_owned()));
            }));
        let client = Client::tracked(
            rocket::build()
                .attach(fairing)
                .mount("/", routes![hello_stateful]),
        )
        .await
        .expect("valid rocket");
        let response = client
            .get("/hello")
            .remote(peer("203.0.113.9"))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        assert!(
            response
                .headers()
                .get_one("X-Content-Type-Options")
                .is_some(),
            "the security headers survive the panicking modifier"
        );
        let seen = seen.lock().expect("sink");
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, "custom_response_modifier");
    }
    #[tokio::test]
    async fn the_log_level_knobs_feed_the_stage_surfaces() {
        // `log_request_level` installs the request-logging stage; the
        // country-verdict composer rides `log_country_check_level` off
        // the observability config.
        let config = SecurityConfig {
            log_request_level: Some(guard_core_engine::security_config::LogLevel::Info),
            log_country_check_level: Some(guard_core_engine::security_config::LogLevel::Debug),
            ..SecurityConfig::default()
        };
        let fairing = GuardFairing::from_security_config(&config).expect("valid");
        assert!(
            fairing.request_logging.is_some(),
            "the level installs the request-logging stage"
        );
        let observability = fairing
            .observability
            .as_ref()
            .expect("country level installs it");
        assert_eq!(
            observability.log_request_level,
            Some(guard_core_rs::logging::LogLevel::Info)
        );
        assert_eq!(
            observability.log_country_check_level,
            Some(guard_core_rs::logging::LogLevel::Debug)
        );

        // The reference default: no request level (no stage), the
        // country level at its INFO default (observability installs).
        let fairing =
            GuardFairing::from_security_config(&SecurityConfig::default()).expect("valid");
        assert!(fairing.request_logging.is_none());
        let observability = fairing
            .observability
            .as_ref()
            .expect("the INFO country default");
        assert_eq!(observability.log_request_level, None);
        assert_eq!(
            observability.log_country_check_level,
            Some(guard_core_rs::logging::LogLevel::Info)
        );
    }

    #[tokio::test]
    async fn the_country_level_alone_installs_observability_and_composes() {
        let config = SecurityConfig {
            log_suspicious_level: None,
            blocked_countries: [String::from("RU")].into_iter().collect(),
            ..SecurityConfig::default()
        };
        let fairing = GuardFairing::from_security_config(&config).expect("valid");
        let observability = fairing.observability.as_ref().expect("the country default");
        assert_eq!(observability.log_suspicious_level, None);

        // A dispatch through the geo position composes the verdict line
        // (the geo stage is a host-provided collaborator).
        let path = "/hello?q=benign";
        let (status, _, _) = full_status(
            GuardFairing::from_security_config(&config)
                .expect("valid")
                .with_geo_blocking(guard_core_rs::geo::GeoStage::new(
                    guard_core_rs::geo::GeoStageConfig {
                        gate: guard_core_engine::geo::parse_country_lists([] as [&str; 0], ["RU"]),
                        handler: None,
                        passive_mode: false,
                    },
                )),
            path,
            "203.0.113.9",
        )
        .await;
        assert_eq!(status, Status::Ok);
    }
    #[tokio::test]
    async fn from_security_config_defaults_screen_clean_traffic() {
        let config = SecurityConfig::default();
        let client =
            tracked_config(GuardFairing::from_security_config(&config).expect("valid")).await;
        let response = client
            .get("/hello")
            .remote(peer_ip([203, 0, 113, 9]))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.into_string().await.as_deref(), Some("ok"));
    }

    #[tokio::test]
    async fn from_security_config_enforce_https_redirects_http() {
        let config = SecurityConfig {
            enforce_https: true,
            ..crate::SecurityConfig::default()
        };
        let client =
            tracked_config(GuardFairing::from_security_config(&config).expect("valid")).await;
        let response = client
            .get("/hello")
            .remote(peer_ip([203, 0, 113, 9]))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::MovedPermanently);
        let location = response
            .headers()
            .get_one("Location")
            .unwrap_or_default()
            .to_owned();
        assert!(
            location.starts_with("https://"),
            "the reference redirect upgrades the scheme: {location}"
        );
    }

    #[tokio::test]
    async fn from_security_config_emergency_mode_blocks_outside_the_whitelist() {
        let config = SecurityConfig {
            emergency_mode: true,
            emergency_whitelist: vec![String::from("198.51.100.7")],
            ..crate::SecurityConfig::default()
        };
        let client =
            tracked_config(GuardFairing::from_security_config(&config).expect("valid")).await;
        let response = client
            .get("/hello")
            .remote(peer_ip([203, 0, 113, 9]))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::ServiceUnavailable);
        let response = client
            .get("/hello")
            .remote(peer_ip([198, 51, 100, 7]))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
    }

    #[tokio::test]
    async fn from_security_config_blocked_user_agent_answers_the_403() {
        let config = SecurityConfig {
            blocked_user_agents: vec![String::from("bad-bot")],
            ..crate::SecurityConfig::default()
        };
        let client =
            tracked_config(GuardFairing::from_security_config(&config).expect("valid")).await;
        let response = client
            .get("/hello")
            .remote(peer_ip([203, 0, 113, 9]))
            .header(rocket::http::Header::new("User-Agent", "bad-bot/1.0"))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Forbidden);
        assert_eq!(
            response.into_string().await.as_deref(),
            Some("User-Agent not allowed")
        );

        let response = client
            .get("/hello")
            .remote(peer_ip([203, 0, 113, 9]))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
    }

    #[tokio::test]
    async fn from_security_config_exclude_paths_bypass_the_pipeline() {
        let config = SecurityConfig {
            blacklist: vec![String::from("203.0.113.9")],
            exclude_paths: vec![String::from("/docs")],
            ..crate::SecurityConfig::default()
        };
        let client =
            tracked_config(GuardFairing::from_security_config(&config).expect("valid")).await;
        // An excluded path bypasses every check, gate included: the
        // blacklisted IP forwards on /docs.
        let response = client
            .get("/docs")
            .remote(peer_ip([203, 0, 113, 9]))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.into_string().await.as_deref(), Some("docs"));
        // Any other path takes the gate denial.
        let response = client
            .get("/hello")
            .remote(peer_ip([203, 0, 113, 9]))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Forbidden);
    }

    #[test]
    fn from_security_config_invalid_ip_list_entry_fails_closed() {
        let config = SecurityConfig {
            whitelist: Some(vec![String::from("not-an-ip")]),
            ..crate::SecurityConfig::default()
        };
        let error = GuardFairing::from_security_config(&config).unwrap_err();
        assert!(matches!(error, crate::GuardConfigError::IpGate(_)));
    }

    #[tokio::test]
    async fn from_security_config_rate_limit_crossing_answers_429() {
        let config = SecurityConfig {
            rate_limit: 1,
            ..crate::SecurityConfig::default()
        };
        let client =
            tracked_config(GuardFairing::from_security_config(&config).expect("valid")).await;
        let first = client
            .get("/hello")
            .remote(peer_ip([203, 0, 113, 9]))
            .dispatch()
            .await;
        assert_eq!(first.status(), Status::Ok);
        let second = client
            .get("/hello")
            .remote(peer_ip([203, 0, 113, 9]))
            .dispatch()
            .await;
        assert_eq!(second.status(), Status::TooManyRequests);
        assert_eq!(second.headers().get_one("Retry-After"), Some("60"));
        assert_eq!(
            second.into_string().await.as_deref(),
            Some(crate::RATE_LIMITED_MESSAGE)
        );
    }

    #[tokio::test]
    async fn from_security_config_custom_error_responses_render() {
        let config = SecurityConfig {
            blacklist: vec![String::from("203.0.113.9")],
            custom_error_responses: {
                let mut map = std::collections::BTreeMap::new();
                map.insert(403, String::from("custom-forbidden"));
                map
            },
            ..crate::SecurityConfig::default()
        };
        let client =
            tracked_config(GuardFairing::from_security_config(&config).expect("valid")).await;
        let response = client
            .get("/hello")
            .remote(peer_ip([203, 0, 113, 9]))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Forbidden);
        // The custom-error body override wins over the family default.
        assert_eq!(
            response.into_string().await.as_deref(),
            Some("custom-forbidden")
        );
    }

    #[tokio::test]
    async fn from_security_config_ip_gate_denial_fires_the_on_block_hook() {
        type HookLog = Arc<std::sync::Mutex<Vec<(String, Option<u16>)>>>;
        let seen: HookLog = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let hook: crate::OnBlockHook = Arc::new(move |payload: &crate::BlockPayload| {
            sink.lock()
                .expect("sink")
                .push((payload.check_name.clone(), payload.status_code));
        });
        let config = SecurityConfig {
            blacklist: vec![String::from("203.0.113.9")],
            on_block: Some(hook),
            ..crate::SecurityConfig::default()
        };
        let client =
            tracked_config(GuardFairing::from_security_config(&config).expect("valid")).await;
        let response = client
            .get("/hello")
            .remote(peer_ip([203, 0, 113, 9]))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Forbidden);
        let seen = seen.lock().expect("sink");
        assert!(
            seen.iter()
                .any(|(check, status)| check == "ip_security" && *status == Some(403)),
            "the reference on_block hook fires once with the ip_security keys: {seen:?}"
        );
    }

    #[tokio::test]
    async fn from_security_config_ip_gate_denial_under_passive_mode_forwards() {
        let config = SecurityConfig {
            passive_mode: true,
            blacklist: vec![String::from("203.0.113.9")],
            ..crate::SecurityConfig::default()
        };
        let client =
            tracked_config(GuardFairing::from_security_config(&config).expect("valid")).await;
        let response = client
            .get("/hello")
            .remote(peer_ip([203, 0, 113, 9]))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.into_string().await.as_deref(), Some("ok"));
    }

    #[tokio::test]
    async fn from_security_config_disabled_rate_limiting_forwards_freely() {
        let config = SecurityConfig {
            enable_rate_limiting: false,
            rate_limit: 1,
            ..crate::SecurityConfig::default()
        };
        let client =
            tracked_config(GuardFairing::from_security_config(&config).expect("valid")).await;
        for _ in 0..3 {
            let response = client
                .get("/hello")
                .remote(peer_ip([203, 0, 113, 9]))
                .dispatch()
                .await;
            assert_eq!(response.status(), Status::Ok);
        }
    }

    #[test]
    fn from_security_config_zero_rate_limit_fails_closed() {
        let config = SecurityConfig {
            rate_limit: 0,
            ..crate::SecurityConfig::default()
        };
        let error = GuardFairing::from_security_config(&config).unwrap_err();
        assert!(matches!(error, crate::GuardConfigError::RateLimit(_)));
    }

    #[tokio::test]
    async fn from_security_config_detection_exclusions_and_categories_reach_the_scan() {
        let config = SecurityConfig {
            enabled_detection_categories: {
                let mut set = std::collections::BTreeSet::new();
                set.insert(String::from("xss"));
                set
            },
            excluded_detection_params: {
                let mut set = std::collections::BTreeSet::new();
                set.insert(String::from("q"));
                set
            },
            detection_scan_body: false,
            ..crate::SecurityConfig::default()
        };
        let client =
            tracked_config(GuardFairing::from_security_config(&config).expect("valid")).await;
        // The sqli category is disabled by the enabled-categories override:
        // the sqli probe forwards.
        let response = client
            .get("/hello?q=1%27+OR+1%3D1")
            .remote(peer_ip([203, 0, 113, 9]))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
    }

    #[tokio::test]
    async fn from_security_config_security_headers_and_cors_render() {
        let config = SecurityConfig {
            enable_cors: true,
            cors_allow_origins: vec![String::from("https://app.test")],
            ..crate::SecurityConfig::default()
        };
        let client =
            tracked_config(GuardFairing::from_security_config(&config).expect("valid")).await;
        let response = client
            .get("/hello")
            .remote(peer_ip([203, 0, 113, 9]))
            .header(rocket::http::Header::new("Origin", "https://app.test"))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(
            response.headers().get_one("x-content-type-options"),
            Some("nosniff")
        );
        assert_eq!(
            response.headers().get_one("access-control-allow-origin"),
            Some("https://app.test")
        );
    }

    #[test]
    fn from_security_config_empty_category_set_skips_the_exclusion_block() {
        // The reference's empty `enabled_detection_categories` frozenset:
        // an explicitly empty set disables every category, and the
        // detection-exclusion block is not installed at all.
        let config = SecurityConfig {
            enabled_detection_categories: std::collections::BTreeSet::new(),
            ..crate::SecurityConfig::default()
        };
        let fairing = GuardFairing::from_security_config(&config).expect("valid config");
        assert!(fairing.detection_exclusions.is_none());
    }

    #[test]
    fn from_security_config_disabled_security_headers_skip_the_processor() {
        let config = SecurityConfig {
            security_headers: guard_core_engine::security_headers::SecurityHeadersConfig {
                enabled: false,
                ..guard_core_engine::security_headers::SecurityHeadersConfig::reference_default()
            },
            ..crate::SecurityConfig::default()
        };
        let fairing = GuardFairing::from_security_config(&config).expect("valid config");
        assert!(fairing.response_processor.is_none());
    }

    #[tokio::test]
    async fn from_security_config_exclude_paths_still_render_the_response_pass() {
        let config = SecurityConfig::default();
        let client =
            tracked_config(GuardFairing::from_security_config(&config).expect("valid")).await;
        let response = client
            .get("/docs")
            .remote(peer_ip([203, 0, 113, 9]))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        // The forwarded response still carries the security-header set: the
        // carve-out bypasses the request-side checks, not the response pass.
        assert_eq!(
            response.headers().get_one("x-content-type-options"),
            Some("nosniff")
        );
    }
}
