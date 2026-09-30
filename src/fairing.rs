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
use guard_core_rs::events::SecurityEventBus;
use guard_core_rs::responses::{CustomErrorResponses, OnBlockHook};
use guard_core_rs::tower::RouteRateResolver;
use guard_core_rs::tower::{ObservabilityConfig, RateLimitStage, RateLimitStageConfig};
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
#[derive(Clone)]
pub struct GuardFairing {
    engine: GuardEngine,
    ip_gate: Option<guard_core_engine::ip_gate::IpGateConfig>,
    route_tiers: Option<RouteRateResolver>,
    geo_handler: Option<std::sync::Arc<dyn GeoIpHandler>>,
    events: Option<std::sync::Arc<SecurityEventBus>>,
    observability: Option<ObservabilityConfig>,
    on_block: Option<OnBlockHook>,
    custom_error_responses: CustomErrorResponses,
    passive_mode: bool,
    distributed: Option<(std::sync::Arc<dyn SlidingWindowStore>, String, bool)>,
    distributed_ban_store: Option<std::sync::Arc<dyn BanStore>>,
    detection_exclusions: Option<DetectionExclusionConfig>,
    route_exclusions: Option<crate::scan::RouteExclusionsResolver>,
    scan_fn: crate::ScanFn,
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
            passive_mode: false,
            distributed: None,
            distributed_ban_store: None,
            detection_exclusions: None,
            route_exclusions: None,
            scan_fn: guard_core_engine::detection_exclusions::scan_request,
        }
    }

    /// Build the fairing with [`crate::default_config`].
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(crate::default_config())
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
        let verdict = metadata_verdict(request);
        if response.status() == Status::NotFound
            && let Some(verdict) = verdict
            && !matches!(verdict, Verdict::Clean | Verdict::Failed)
        {
            *response = response::verdict_response(request, verdict);
        }
    }
}

impl GuardFairing {
    /// The request's verdict: the IP gate first (a denied client IP is the
    /// verdict, no scan needed), then the stateful stage (dynamic bans, then
    /// rate limiting), then the metadata views, each recovered from an engine
    /// panic as fail-secure.
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
        if let Some(gate) = &self.ip_gate
            && let Some(ip) = request.client_ip()
        {
            match gate.evaluate(ip) {
                IpGateVerdict::Denied(_) => return Verdict::IpBlocked,
                IpGateVerdict::Allowed(decision) => record_gate_decision(request, decision),
            }
        }

        // The metadata views (path, query, headers) scan first; the body
        // view scans later, in the route's data guard - Rocket's
        // `on_request` never sees the body, which is why this adapter's
        // flow is two-phase (see the module docs).
        let Ok(metadata) = catch_unwind(AssertUnwindSafe(|| engine.scan_metadata(request))) else {
            return Verdict::Failed;
        };

        // One engine-stage pass decides for every request: bans first (403
        // `IP address banned`), then the rate-limit tiers (429 +
        // `Retry-After`), then the metadata finding (the auto-ban engine
        // may answer `403 IP has been banned` on this very request) - the
        // reference pipeline order. The window records exactly once here;
        // the body finding feeds later through `feed_finding`.
        if let Some((verdict, _)) = stage_decision(engine, request, metadata.as_ref()) {
            return verdict;
        }

        match metadata {
            Some(verdict) => metadata_threat_verdict(engine, request, &verdict),
            None => Verdict::Clean,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
