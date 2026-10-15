//! # rocket-guard-rs
//!
//! Application-layer security middleware for
//! [Rocket](https://rocket.rs) 0.5, powered by the
//! [guard-core-rs](https://github.com/Guard-Core/guard-core-rs) detection
//! engine. Part of the [Guard ecosystem](https://github.com/Guard-Core).
//!
//! ## Status: implemented (v0.1.0)
//!
//! [`GuardFairing`] screens every request through the engine,
//! [`BlockGuard`] and [`GuardBody`] enforce the verdict before a route
//! handler runs. The engine is wired in through `guard-core-engine` (a path
//! dependency until the engine is tagged and published). Per the ecosystem
//! boundary rules, this adapter holds framework glue only: every detection
//! decision comes from the engine.
//!
//! ## Wiring: two steps, because Rocket needs two
//!
//! Rocket has no middleware chain that can abort a request. A fairing's
//! `on_request` cannot short-circuit (there is no outcome return), and a
//! request guard cannot read bodies. Rocket's own source rejects the idea of
//! making request fairings abortable, calling request guards "the correct
//! mechanism". The adapter therefore splits the work the way Rocket
//! requires:
//!
//! 1. **Attach [`GuardFairing`]** (`Kind::Ignite | Kind::Request |
//!    Kind::Response`). Its `on_request` scans the path, query, and header
//!    views and stashes the verdict in request-local state. Its `on_ignite`
//!    registers the `400`/`403`/`413`/`429`/`500` catchers that render
//!    refusals as the
//!    ecosystem's plain-text error shape (skipping any status the application
//!    already registered a catcher for, because Rocket treats same-code
//!    catchers at the same base as a fatal collision).
//! 2. **Add a guard argument to each protected route**: [`BlockGuard`] for
//!    routes without a body, [`GuardBody`] for routes with one. This is the
//!    part Rocket cannot do for you: protection is per-route, and the guard
//!    argument is Rocket's own mechanism for it.
//!
//! ```no_run
//! use rocket::{get, post, routes};
//! use rocket_guard_rs::{BlockGuard, GuardBody, GuardFairing, default_config};
//!
//! #[get("/health")]
//! fn health(_guard: BlockGuard) -> &'static str {
//!     "ok"
//! }
//!
//! #[post("/submit", data = "<body>")]
//! fn submit(body: GuardBody) -> Vec<u8> {
//!     body.into_inner()
//! }
//!
//! #[rocket::launch]
//! fn rocket() -> _ {
//!     rocket::build()
//!         .attach(GuardFairing::new(default_config()))
//!         .mount("/", routes![health, submit])
//! }
//! ```
//!
//! Routes without either guard argument are scanned but not blocked; the
//! fairing additionally rewrites a `404` to the verdict's guarded refusal
//! shape when the verdict is a block, so a threat to a path that matches no
//! route does not leak a `404`. A `404` is proof that no handler ran, which is why that
//! rewrite is safe; a route that *did* run cannot be un-run, so the guard
//! argument is the only real enforcement point.
//!
//! ## What it inspects
//!
//! One engine call per request view, mirroring the mapping used by the
//! sibling adapters (`tower-guard-rs`, `actix-guard-rs`, `guard-core-ts`):
//!
//! | Request part | Engine context | Notes |
//! |---|---|---|
//! | Path | `url_path` | Skipped for `/` |
//! | Query string | `query_param` | Skipped when empty |
//! | Header values | `header` | Skips `sec-*` and hop-by-hop/negotiation headers (see `EXCLUDED_HEADERS` in `src/scan.rs`) |
//! | Body | `request_body` | Buffered by [`GuardBody`], capped (see below) |
//!
//! The HTTP method is not fed to the engine: the engine's `detect` signature
//! takes content plus a context, and the reference adapters do not scan the
//! method either.
//!
//! ## Body scanning and the cap
//!
//! Rocket streams request bodies and hands them to a route's data guard; a
//! fairing can only peek at the first 512 bytes (`Data::peek` is capped at
//! `PEEK_BYTES`). Scanning a truncated prefix as if it were the body would be
//! a bypass vector, so the body view is scanned by [`GuardBody`], which owns
//! the data stream.
//!
//! Bodies are buffered up to the cap configured on
//! [`GuardFairing::with_body_cap`], defaulting to the engine's full-scan cap
//! (`DetectConfig::max_full_scan_bytes`, 262,144 bytes in the ecosystem
//! default). A request whose body exceeds the cap is refused with
//! `413 Payload Too Large` rather than forwarded unscanned. Rocket's own
//! `limits` continue to apply inside handlers; a limit violation raised by
//! Rocket's guards (for example `Json`) is also a `413` error outcome, and
//! therefore also gets the `Payload too large` body.
//!
//! ## Responses
//!
//! | Situation | Status | Body |
//! |---|---|---|
//! | The IP gate denies the client IP (blacklisted, or a non-empty whitelist matches neither the IP nor an exemption) | `403 Forbidden` | `Forbidden` |
//! | The ban stage finds a live ban on the client IP | `403 Forbidden` | `IP address banned` |
//! | The rate limiter records a crossing of `rate_limit` | `429 Too Many Requests` (+ `Retry-After: <window>`) | `Too many requests` |
//! | Engine flags a view | `400 Bad Request` | `Suspicious activity detected` |
//! | Engine flags a view and the crossed auto-ban threshold bans on the spot | `403 Forbidden` | `IP has been banned` |
//! | Body exceeds the cap | `413 Payload Too Large` | `Payload too large` |
//! | Body read error or engine panic | `500 Internal Server Error` | `Security check failed` |
//!
//! The IP gate is optional (`GuardFairing::with_ip_gate`); when it is
//! configured, `exempt_ips` (like a whitelist match) only sets the skip state
//! on the request, never a deny path of its own - the exempt-vs-whitelist
//! contract in the engine's `ip_gate` module. The stateful stages honor that
//! contract: the rate limiter (`GuardFairing::with_rate_limiting`) and the
//! ban/auto-ban stage (`GuardFairing::with_ip_banning`) skip whitelisted and
//! exempt IPs for exactly what the reference skips (rate limiting, violation
//! counting, banning) and never skip detection, which always scans every
//! request, exempt or not.
//!
//! ## The full stage surface (the reference 17-check pipeline, wired)
//!
//! Every reference check the engine ships is now installable on
//! [`GuardFairing`], and the fairing runs the installed set in the
//! reference pipeline order (the stateful pass splits at the reference
//! seams: the ban arm before geo/cloud/user-agent, the rate-limit tiers
//! after, and the HTTPS redirect renders in the fairing's `on_response`
//! pass, because Rocket catchers are `400`-`599` only):
//!
//! | Reference check | Builder |
//! |---|---|
//! | 2 `emergency_mode` | [`GuardFairing::with_emergency_mode`] |
//! | 3 `https_enforcement` | [`GuardFairing::with_https_enforcement`] |
//! | 4 `request_logging` | [`GuardFairing::with_request_logging`] |
//! | 5 `request_size_content` | [`GuardFairing::with_body_cap`] (413) |
//! | 6 + 7 `required_headers` / authentication | [`GuardFairing::with_headers_auth`] |
//! | 8 referrer | [`GuardFairing::with_referrer_gate`] |
//! | 9 `custom_validators` | [`GuardFairing::with_custom_checks`] |
//! | 10 `time_window` | [`GuardFairing::with_time_window_gate`] |
//! | 12b geo country blocking | [`GuardFairing::with_geo_blocking`] |
//! | 13 `cloud_provider` | [`GuardFairing::with_cloud_provider`] |
//! | 14 `user_agent` | [`GuardFairing::with_user_agent`] |
//! | 12a / 15 / 16 bans / `rate_limit` / detection feed | [`GuardFairing::with_rate_limiting`] + [`GuardFairing::with_ip_banning`] |
//! | 17 `custom_request` | [`GuardFairing::with_custom_checks`] |
//! | response pass (return rules + security headers + CORS) | [`GuardFairing::with_response_processor`] |
//!
//! ## The unified configuration surface
//!
//! [`GuardFairing::from_security_config`] builds the whole wired pipeline
//! from the engine's [`SecurityConfig`] (the reference configuration
//! surface) through the facade's [`Wiring`], the one mapping every Rust
//! adapter shares (the field-by-field table is in the
//! [`guard_core_rs::wiring`] module docs). Geo country rules and
//! `geo_ip_handler`, `block_cloud_providers` (with the per-request range
//! refresh), `endpoint_rate_limits`, the rate-limit auto-ban,
//! `custom_request_check`, `auth_verifier` (the fallback of a route's
//! verifiers), `custom_response_modifier`, `on_error`, `cors_expose_headers`,
//! the telemetry sink, the event bus and the dynamic rules all land on the
//! fairing. Invalid values fail closed through the typed
//! [`GuardConfigError`]. [`GuardFairing::from_security_config_with`] takes
//! the collaborators a config cannot carry: the telemetry agent (any
//! [`TelemetryHandler`], for example guard-agent-rs's `GuardAgentTelemetry`
//! built from the `agent_*` fields) and the Logfire client. Wiring starts
//! nothing: [`GuardFairing::telemetry`] exposes the fan-out for the host to
//! `start()` / `stop()`, and [`GuardFairing::spawn_dynamic_rules`] starts the
//! dynamic-rule poll loop. `route_resolution_strict` is not applied (Rocket
//! resolves routes after `on_request`) and stays on the config.
//!
//! ## Client resolution
//!
//! The identity every stage runs under (gate, bans, rate limit, geo, cloud,
//! events, the response pass) is resolved from the connecting peer with the
//! reference rules: `X-Forwarded-For` counts only behind a trusted proxy
//! (`trusted_proxies`, `trusted_proxy_depth`) and an IPv4-mapped IPv6 peer
//! is canonicalized. Rocket's own `Request::client_ip()` is never used: it
//! honors the `X-Real-IP` header from any peer. A request with no peer and
//! no resolvable client answers `403 Client address could not be
//! determined` under `fail_secure` (check name `client_address_unresolved`
//! on the `on_block` hook) before any check, and continues unattributed
//! under `fail_secure = false`. A bare fairing defaults to no proxies and
//! `fail_secure = false`; [`GuardFairing::with_client_policy`] installs a
//! [`ClientPolicy`] and `from_security_config` installs the config's
//! (`fail_secure` defaults to `true`). The HTTPS stage matches
//! `trusted_proxies` against the connecting peer and takes the transport's
//! own scheme, so a forged `X-Forwarded-Proto` does not skip the redirect.
//!
//! ## Excluded paths and bypassed routes
//!
//! `exclude_paths` uses the reference matcher: `/static` covers `/static`
//! and `/static/app.js` (never `/staticx`) and percent-encoding and dot
//! segments are resolved before matching. An excluded request is scoped,
//! not bypassed: it carries [`GuardExclusionScoped`] and runs route
//! resolution, the ban check, the global IP lists, country and cloud rules
//! and the rate limit. Emergency mode, HTTPS enforcement, request logging,
//! headers and auth, validators, the scan (the [`GuardBody`] body scan
//! included, its size cap stays as the memory bound), the user-agent
//! filter, custom checks and the return rules are skipped. The response
//! still gets the metrics, security headers, CORS and the modifier. The CORS
//! preflight short-circuit runs before the exclusion decision. A route
//! carrier that bypasses `all` checks emits the `security_bypass` event,
//! runs no check and gets only the response modifier (under `passive_mode`
//! it continues through the pipeline). Rocket cannot answer from
//! `on_request`, so every refusal here rides the same verdict, guard and
//! catcher path as any other block.
//!
//! ## The response pass
//!
//! The modifier of the processor (from the config) and the fairing's
//! ([`GuardFairing::with_custom_response_modifier`]) each run once, and the
//! fairing's runs even without a processor. Body `return_pattern` rules
//! read the response body: when a rule needs it
//! (`behavior_scan_response_body`) the response body is buffered in full
//! (bounded in time by `body_read_timeout`; a read error or timeout answers
//! the fail-secure `500`) and re-emitted intact, and the first
//! `behavior_max_response_body_inspect_bytes` bytes are what the rules read.
//! Status-only rules never buffer; do not combine body rules with endless
//! streaming responses.
//!
//! These bodies follow the ecosystem's plain-text convention (the bare
//! message, `text/plain; charset=utf-8`, same as the Python family)
//! but the adapter is deliberately **fail-secure**, unlike the TypeScript
//! adapters whose check pipeline logs and skips on error: any failure to
//! complete the security check results in `500`, never in an uninspected
//! passthrough.
//!
//! A panic is caught with [`std::panic::catch_unwind`], so the default panic
//! hook still prints. `panic = "abort"` in the release profile disables that
//! recovery, because the process dies before the guard can respond.

mod fairing;
mod guards;
mod response;
mod scan;

pub mod status;
pub mod websocket;

pub use crate::fairing::AgentStats;
pub use crate::fairing::GuardFairing;
pub use crate::guards::{BlockGuard, GuardBody, GuardBodyError, GuardExclusionScoped};
pub use crate::response::{
    ACTIVITY_BANNED_MESSAGE, BANNED_MESSAGE, BLOCKED_MESSAGE, FAILURE_MESSAGE, FORBIDDEN_MESSAGE,
    OVERSIZE_MESSAGE, RATE_LIMITED_MESSAGE, guard_catchers,
};
pub use crate::scan::{set_route_config, set_route_detection_exclusions, set_route_rate_limits};
pub use crate::websocket::{
    WebSocketCloseReason, WebSocketGuard, WebSocketGuardConfig, WsGuardError, make_guard_websocket,
    run_websocket_checks,
};
pub use guard_core_engine::detect::{DetectConfig, DetectVerdict, Threat};
pub use guard_core_engine::detection_exclusions::{
    DetectionExclusionConfig, RouteDetectionExclusions,
};
pub use guard_core_engine::distributed::{BanStore, SlidingWindowStore};
pub use guard_core_engine::geo::GeoIpHandler;
pub use guard_core_engine::headers_auth::AuthVerifier;
pub use guard_core_engine::ip_ban::{
    BanError, BanRecord, Clock, IpBanConfig, IpBanConfigError, IpBanManager, ResolvedBan,
    ThreatBanEntry, ViolationCounters,
};
pub use guard_core_engine::ip_gate::{
    IpGateConfig, IpGateDecision, IpGateDenial, IpGateError, IpGateVerdict,
};
pub use guard_core_engine::path_matching::PathExclusions;
pub use guard_core_engine::rate_limit::{
    RateLimitConfig, RateLimitConfigError, RateLimitDecision, RateLimitEntry, RateLimitTier,
    RateLimiter, RouteRateLimits, TierDecision,
};
pub use guard_core_engine::route_config::{RouteConfig, RouteConfigResolver};
pub use guard_core_engine::security_config::{
    BufferOverflowPolicy, LogFormat, LogLevel, SecurityConfig, SecurityConfigError,
};
pub use guard_core_engine::security_headers::SecurityHeadersConfig;
pub use guard_core_rs::composite::{CompositeAgentHandler, TelemetryHandler};
pub use guard_core_rs::events::SecurityEventBus;
pub use guard_core_rs::metrics::MetricsCollector;
pub use guard_core_rs::responses::{BlockPayload, CustomErrorResponses, OnBlockHook};
pub use guard_core_rs::tower::{
    ObservabilityConfig, RateLimitStage, RateLimitStageConfig, RequestObservation, StageResponse,
};
pub use guard_core_rs::wiring::{
    ClientPolicy, CloudRefresh, Distributed, DynamicRules, DynamicRulesHandle, Wiring, WiringError,
    WiringOptions,
};

/// The multi-surface scan entry point stored in the engine.
///
/// Indirection exists so unit tests can substitute a panicking scan and
/// exercise the fail-secure path; production builds always store
/// [`guard_core_engine::detection_exclusions::scan_request`].
pub(crate) type ScanFn = fn(
    &guard_core_engine::detection_exclusions::RequestSurfaces<'_>,
    &guard_core_engine::detection_exclusions::ResolvedExclusions,
    &DetectConfig,
) -> guard_core_engine::detection_exclusions::RequestScanVerdict;

/// The stateful stage's ban half: the shared ban store, the shared violation
/// counters (one fairing = one store pair), and the config that gates banning
/// and threshold resolution.
pub(crate) struct BanState {
    manager: IpBanManager,
    counters: ViolationCounters,
    config: IpBanConfig,
}

impl core::fmt::Debug for BanState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BanState")
            .field("manager", &self.manager)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// Reference default detection configuration.
///
/// The engine's [`DetectConfig`] carries no `Default` impl, so the adapter
/// pins the ecosystem defaults here. They are the values the conformance
/// corpus records for the reference implementation:
///
/// | Knob | Value |
/// |---|---|
/// | `max_content_length` | `10_000` |
/// | `max_full_scan_bytes` | `262_144` |
/// | `preserve_attack_patterns` | `true` |
/// | `semantic_threshold` | `0.7` |
/// | `threat_score_threshold` | `1.0` |
/// | `binary_min_run_length` | `16` |
///
/// # Example
///
/// ```
/// let config = rocket_guard_rs::default_config();
/// let fairing = rocket_guard_rs::GuardFairing::new(config);
/// # let _ = fairing;
/// ```
#[must_use]
pub const fn default_config() -> DetectConfig {
    DetectConfig {
        max_content_length: 10_000,
        max_full_scan_bytes: 262_144,
        preserve_attack_patterns: true,
        semantic_threshold: 0.7,
        threat_score_threshold: 1.0,
        binary_min_run_length: 16,
        max_scan_values: 512,
        max_scan_chars: 65_536,
        max_json_depth: 32,
    }
}

/// Why [`GuardFairing::from_security_config`] refused a value: the engine
/// constructor that rejected it, fail-closed.
#[derive(Debug)]
pub enum GuardConfigError {
    /// An IP/CIDR list entry the gate cannot parse.
    IpGate(IpGateError),
    /// A zero rate-limit knob.
    RateLimit(RateLimitConfigError),
    /// A blocked user-agent pattern the `ReDoS` validator rejected.
    UserAgent(guard_core_engine::user_agent::UserAgentConfigError),
    /// An invalid auto-ban knob group.
    Ban(IpBanConfigError),
    /// A `block_cloud_providers` selector the engine does not know.
    Cloud(guard_core_engine::cloud_provider::CloudConfigError),
    /// `enable_redis` without a `redis_url`, or the backend refused it.
    Redis(String),
    /// Country rules without a resolver, or the `GeoIP` database could not
    /// be set up.
    Geo(String),
}

impl std::fmt::Display for GuardConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IpGate(error) => write!(f, "ip list: {error}"),
            Self::RateLimit(error) => write!(f, "rate limit: {error}"),
            Self::UserAgent(error) => write!(f, "blocked user agent: {error}"),
            Self::Ban(error) => write!(f, "ip ban: {error}"),
            Self::Cloud(error) => write!(f, "block_cloud_providers: {error}"),
            Self::Redis(message) => write!(f, "redis: {message}"),
            Self::Geo(message) => write!(f, "geo: {message}"),
        }
    }
}

impl std::error::Error for GuardConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IpGate(error) => Some(error),
            Self::RateLimit(error) => Some(error),
            Self::UserAgent(error) => Some(error),
            Self::Ban(error) => Some(error),
            Self::Cloud(error) => Some(error),
            Self::Redis(_) | Self::Geo(_) => None,
        }
    }
}

impl From<IpGateError> for GuardConfigError {
    fn from(error: IpGateError) -> Self {
        Self::IpGate(error)
    }
}

impl From<RateLimitConfigError> for GuardConfigError {
    fn from(error: RateLimitConfigError) -> Self {
        Self::RateLimit(error)
    }
}

impl From<guard_core_engine::user_agent::UserAgentConfigError> for GuardConfigError {
    fn from(error: guard_core_engine::user_agent::UserAgentConfigError) -> Self {
        Self::UserAgent(error)
    }
}

impl From<IpBanConfigError> for GuardConfigError {
    fn from(error: IpBanConfigError) -> Self {
        Self::Ban(error)
    }
}

impl From<WiringError> for GuardConfigError {
    fn from(error: WiringError) -> Self {
        match error {
            WiringError::IpGate(error) => Self::IpGate(error),
            WiringError::RateLimit(error) => Self::RateLimit(error),
            WiringError::UserAgent(error) => Self::UserAgent(error),
            WiringError::Ban(error) => Self::Ban(error),
            WiringError::Cloud(error) => Self::Cloud(error),
            WiringError::Redis(message) => Self::Redis(message),
            WiringError::Geo(message) => Self::Geo(message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_matches_corpus_knobs() {
        let config = default_config();
        assert_eq!(config.max_content_length, 10_000);
        assert_eq!(config.max_full_scan_bytes, 262_144);
        assert!(config.preserve_attack_patterns);
        assert!((config.semantic_threshold - 0.7).abs() < f64::EPSILON);
        assert!((config.threat_score_threshold - 1.0).abs() < f64::EPSILON);
        assert_eq!(config.binary_min_run_length, 16);
    }

    #[test]
    fn body_cap_defaults_to_full_scan_cap_and_is_overridable() {
        let fairing = GuardFairing::with_defaults();
        assert_eq!(fairing.engine_body_cap(), 262_144);
        let fairing = fairing.with_body_cap(1024);
        assert_eq!(fairing.engine_body_cap(), 1024);
    }

    #[test]
    fn guard_config_error_display_and_source_cover_every_variant() {
        let ip_gate: GuardConfigError = IpGateError {
            list: "whitelist",
            entry: String::from("nope"),
        }
        .into();
        assert!(ip_gate.to_string().contains("ip list"));
        assert!(std::error::Error::source(&ip_gate).is_some());

        let rate_limit: GuardConfigError = RateLimitConfigError {
            field: std::borrow::Cow::Borrowed("rate_limit"),
            reason: "must be at least 1",
        }
        .into();
        assert!(rate_limit.to_string().contains("rate limit"));
        assert!(std::error::Error::source(&rate_limit).is_some());

        let user_agent: GuardConfigError = guard_core_engine::user_agent::UserAgentConfigError {
            entry: String::from("bad-bot"),
            reason: String::from("rejected"),
        }
        .into();
        assert!(user_agent.to_string().contains("blocked user agent"));
        assert!(std::error::Error::source(&user_agent).is_some());

        let ban: GuardConfigError = IpBanConfigError::NonPositive {
            field: "auto_ban_threshold",
        }
        .into();
        assert!(ban.to_string().contains("ip ban"));
        assert!(std::error::Error::source(&ban).is_some());
    }

    #[test]
    fn from_security_config_exclude_paths_round_trip_through_the_accessor() {
        let config = SecurityConfig {
            exclude_paths: vec![String::from("/docs")],
            ..SecurityConfig::default()
        };
        let fairing = GuardFairing::from_security_config(&config).expect("valid config");
        assert_eq!(fairing.exclude_paths(), ["/docs"]);
    }

    #[test]
    fn with_exclude_paths_round_trips_through_the_accessor() {
        let fairing = GuardFairing::with_defaults()
            .with_exclude_paths(vec![String::from("/docs"), String::from("/static")]);
        assert_eq!(fairing.exclude_paths(), ["/docs", "/static"]);
    }

    #[test]
    fn every_wiring_error_maps_onto_its_config_error() {
        use guard_core_engine::cloud_provider::parse_cloud_selectors;
        let user_agent = guard_core_engine::user_agent::UserAgentFilter::new(["(a+)+$"])
            .err()
            .map(WiringError::UserAgent);
        let ip_gate = IpGateConfig::new(["not-an-ip"], [] as [&str; 0], [] as [&str; 0])
            .err()
            .map(WiringError::IpGate);
        let rate = RateLimiter::new(RateLimitConfig {
            rate_limit: 0,
            ..RateLimitConfig::default()
        })
        .err()
        .map(WiringError::RateLimit);
        let ban = Some(WiringError::Ban(IpBanConfigError::NonPositive {
            field: "auto_ban_threshold",
        }));
        let cloud = parse_cloud_selectors(["NotACloud"])
            .err()
            .map(WiringError::Cloud);
        let converted: Vec<GuardConfigError> = [user_agent, ip_gate, rate, ban, cloud]
            .into_iter()
            .flatten()
            .chain([
                WiringError::Redis("r".to_owned()),
                WiringError::Geo("g".to_owned()),
            ])
            .map(GuardConfigError::from)
            .collect();
        assert!(matches!(converted[0], GuardConfigError::UserAgent(_)));
        assert!(matches!(converted[1], GuardConfigError::IpGate(_)));
        assert!(matches!(converted[2], GuardConfigError::RateLimit(_)));
        assert!(matches!(converted[3], GuardConfigError::Ban(_)));
        assert!(matches!(converted[4], GuardConfigError::Cloud(_)));
        assert!(matches!(converted[5], GuardConfigError::Redis(_)));
        assert!(matches!(converted[6], GuardConfigError::Geo(_)));
    }

    #[test]
    fn ban_state_debug_renders_the_manager_and_config() {
        let entries: Vec<(String, ThreatBanEntry)> = Vec::new();
        let state = BanState {
            manager: IpBanManager::new(),
            counters: ViolationCounters::new(),
            config: IpBanConfig::new(true, 10, 3600, entries).expect("valid config"),
        };
        let rendered = format!("{state:?}");
        assert!(rendered.starts_with("BanState"), "{rendered}");
    }
}
