//! The WebSocket guard, ported from fastapi-guard `guard/websocket.py`
//! (`make_guard_websocket` / `_run_websocket_checks`): the security sequence
//! a WebSocket connection must pass, plus per-frame penetration detection
//! over the live channel, in the `rocket_ws` idiom.
//!
//! Rocket 0.5 does expose a WebSocket surface: the official
//! [`rocket_ws`](https://crates.io/crates/rocket_ws) crate hangs the upgrade
//! off Rocket's connection-upgrade API (`WebSocket` request guard + a
//! `Channel` responder). There is no framework-level interception point
//! before the handshake *response* is rendered, so the guard takes the
//! route-declaration shape Rocket requires: the app installs
//! [`make_guard_websocket`]'s [`WebSocketGuard`] into managed state and
//! declares the [`WebSocketGuard`] request guard on its `rocket_ws` routes.
//! A blocked handshake is rejected with `403 Forbidden` pre-accept, carrying
//! the close shape on dedicated headers ([`WS_CLOSE_CODE_HEADER`] /
//! [`WS_CLOSE_REASON_HEADER`]) - Starlette's `WebSocketException(code,
//! reason)` denial is the reference shape being translated.
//!
//! The check sequence is the reference's:
//!
//! 1. an undeterminable client address fails the handshake closed under
//!    `fail_secure` ([`WS_CLOSE_CLIENT_ADDRESS_UNKNOWN`]);
//! 2. a live IP ban ([`WS_CLOSE_IP_BANNED`]);
//! 3. `is_ip_allowed`: the global IP gate lists and the country rules
//!    ([`WS_CLOSE_IP_NOT_ALLOWED`]; a whitelist match skips the countries);
//! 4. the rate limit over the `ws` endpoint ([`WS_CLOSE_RATE_LIMIT_EXCEEDED`];
//!    skipped for whitelisted IPs, exactly like the reference's
//!    `not config.whitelist` gate);
//! 5. penetration detection over the path, query, and header views - an
//!    upgrade carries no body ([`WS_CLOSE_SUSPICIOUS_ACTIVITY`]).
//!
//! The close codes are the reference's: every policy denial is
//! [`WS_1008_POLICY_VIOLATION`], an engine malfunction is
//! [`WS_1013_TRY_AGAIN_LATER`] ([`WS_CLOSE_SECURITY_CHECK_FAILED`]). The
//! engine primitives the sequence runs on are infallible, so the 1013 shape
//! is reachable through exactly the reference's remaining arm: the check
//! machinery panicking mid-handshake, which [`WebSocketGuard`] contains.
//!
//! ## Shared suspicious counts and the per-frame guard
//!
//! The reference's WS detection shares the HTTP pipeline's
//! `suspicious_request_counts` dict, so a flagged connection counts toward
//! the same auto-ban thresholds as flagged requests. The Rust counterpart
//! is the engine's `ViolationCounters`:
//! [`WebSocketGuardConfig::with_violation_feed`] installs the counter store
//! (and the `IpBanConfig` that resolves thresholds) the guard feeds on every
//! detection - handshake scan and per-frame scan alike. A crossed threshold
//! bans the address in
//! the shared [`IpBanManager`], and the *next* handshake's ban arm then
//! rejects it with [`WS_CLOSE_IP_BANNED`]; the current connection still
//! closes with [`WS_CLOSE_SUSPICIOUS_ACTIVITY`], exactly like the
//! reference's single close arm for any non-malfunction detection block.
//!
//! Frames after the upgrade are the connection's real payload surface, so
//! the guard also mirrors the reference's detection callable at frame
//! granularity: [`WebSocketGuard::scan_frame`] scans one text or binary
//! message through the engine (control frames pass untouched), feeds the
//! shared violation store on a threat, and reports the close shape the
//! channel must answer with. The route's channel loop applies it per
//! message:
//!
//! ```rust,no_run
//! use rocket::futures::{SinkExt, StreamExt};
//! use rocket::{get, routes};
//! use rocket_ws as ws;
//! use rocket_guard_rs::websocket::{
//!     make_guard_websocket, WebSocketGuard, WebSocketGuardConfig, WsGuardError,
//! };
//!
//! #[get("/ws")]
//! fn echo(
//!     guard: Result<WebSocketGuard, WsGuardError>,
//!     ws: ws::WebSocket,
//! ) -> Result<ws::Channel<'static>, WsGuardError> {
//!     let guard = guard?;
//!     Ok(ws.channel(move |mut stream| {
//!         Box::pin(async move {
//!             while let Some(message) = stream.next().await {
//!                 let message = message?;
//!                 if let Err(reason) = guard.scan_frame(None, &message) {
//!                     stream
//!                         .send(WebSocketGuard::close_frame(reason))
//!                         .await?;
//!                     return Err(WebSocketGuard::stream_error(reason));
//!                 }
//!                 stream.send(message).await?;
//!             }
//!             Ok(())
//!         })
//!     }))
//! }
//!
//! #[rocket::launch]
//! fn rocket() -> _ {
//!     let guard = make_guard_websocket(WebSocketGuardConfig::new(
//!         rocket_guard_rs::default_config(),
//!     ));
//!     rocket::build().manage(guard).mount("/", routes![echo])
//! }
//! ```
//!
//! The client IP resolves through Rocket's `Request::client_ip()` (the
//! connection peer, or whatever the host resolves it to). `scan_frame`'s
//! `client_ip` argument takes the same identity - capture it from the
//! request (a `Result<WebSocketGuard, _>` handler can read
//! `rocket::Request::client_ip()` through a request guard of its own, or
//! pass `None` to skip the stateful arms).

use guard_core_engine::detect::DetectConfig;
use guard_core_engine::detection_exclusions::{
    DetectionExclusionConfig, RequestScanVerdict, RequestSurfaces, ResolvedExclusions,
    resolve as resolve_exclusions, scan_request,
};
use guard_core_engine::geo::{CountryGate, GeoIpHandler, check_countries};
use guard_core_engine::ip_ban::{IpBanConfig, IpBanManager, ViolationCounters};
use guard_core_engine::ip_gate::{IpGateConfig, IpGateVerdict};
use guard_core_engine::rate_limit::RateLimiter;
use rocket::Request;
use rocket::http::{HeaderMap, Status};
use rocket::request::{FromRequest, Outcome};
use rocket::response::{self, Responder};
use rocket_ws::{Message, frame::CloseCode, frame::CloseFrame};
use std::borrow::Cow;
use std::io::Cursor;
use std::net::IpAddr;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

/// `WS_1008_POLICY_VIOLATION`: every policy denial's close code.
pub const WS_1008_POLICY_VIOLATION: u16 = 1008;

/// `WS_1013_TRY_AGAIN_LATER`: the engine-malfunction close code.
pub const WS_1013_TRY_AGAIN_LATER: u16 = 1013;

/// One of the reference's close shapes (the `WS_CLOSE_*` table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebSocketCloseReason {
    /// The WebSocket close code.
    pub code: u16,
    /// The close reason phrase.
    pub reason: &'static str,
}

/// `IP banned` - a live ban on the client IP.
pub const WS_CLOSE_IP_BANNED: WebSocketCloseReason = WebSocketCloseReason {
    code: WS_1008_POLICY_VIOLATION,
    reason: "IP banned",
};

/// `IP not allowed` - the `is_ip_allowed` family: gate lists, country rules.
pub const WS_CLOSE_IP_NOT_ALLOWED: WebSocketCloseReason = WebSocketCloseReason {
    code: WS_1008_POLICY_VIOLATION,
    reason: "IP not allowed",
};

/// `Rate limit exceeded` - the `ws` endpoint window crossed.
pub const WS_CLOSE_RATE_LIMIT_EXCEEDED: WebSocketCloseReason = WebSocketCloseReason {
    code: WS_1008_POLICY_VIOLATION,
    reason: "Rate limit exceeded",
};

/// `Client address could not be determined` - the fail-secure unknown
/// address denial.
pub const WS_CLOSE_CLIENT_ADDRESS_UNKNOWN: WebSocketCloseReason = WebSocketCloseReason {
    code: WS_1008_POLICY_VIOLATION,
    reason: "Client address could not be determined",
};

/// `Security check failed` - the engine-malfunction denial, try again later.
pub const WS_CLOSE_SECURITY_CHECK_FAILED: WebSocketCloseReason = WebSocketCloseReason {
    code: WS_1013_TRY_AGAIN_LATER,
    reason: "Security check failed",
};

/// `Suspicious activity detected` - a scanned view produced a threat.
pub const WS_CLOSE_SUSPICIOUS_ACTIVITY: WebSocketCloseReason = WebSocketCloseReason {
    code: WS_1008_POLICY_VIOLATION,
    reason: "Suspicious activity detected",
};

/// The response header carrying the close code on a rejected handshake.
pub const WS_CLOSE_CODE_HEADER: &str = "x-guard-websocket-close";

/// The response header carrying the close reason on a rejected handshake.
pub const WS_CLOSE_REASON_HEADER: &str = "x-guard-websocket-close-reason";

/// Whether the request is a WebSocket upgrade: an `Upgrade: websocket`
/// header plus an `upgrade` token in `Connection` (the token list may carry
/// other connections, e.g. `keep-alive, Upgrade`).
#[must_use]
pub fn is_websocket_upgrade(headers: &HeaderMap<'_>) -> bool {
    let upgrade_ok = headers
        .get("Upgrade")
        .any(|value| value.trim().eq_ignore_ascii_case("websocket"));
    if !upgrade_ok {
        return false;
    }
    headers.get("Connection").any(|value| {
        value
            .split(',')
            .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
    })
}

/// The shared-suspicious-counts feed (the reference's shared
/// `suspicious_request_counts` dict): the violation store the guard records
/// detections into, plus the ban configuration that resolves the thresholds.
#[derive(Clone)]
pub struct ViolationFeed {
    counters: ViolationCounters,
    ban_config: IpBanConfig,
}

impl ViolationFeed {
    /// Pair a violation store with the ban configuration that resolves its
    /// thresholds. Share one [`ViolationCounters`] clone across the guard
    /// and any other consumer to make the counts shared state.
    #[must_use]
    pub const fn new(counters: ViolationCounters, ban_config: IpBanConfig) -> Self {
        Self {
            counters,
            ban_config,
        }
    }

    /// The violation store the feed records into (clones share the store).
    #[must_use]
    pub const fn counters(&self) -> &ViolationCounters {
        &self.counters
    }
}

impl core::fmt::Debug for ViolationFeed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ViolationFeed")
            .field("counters", &self.counters)
            .field("ban_config", &self.ban_config)
            .finish_non_exhaustive()
    }
}

/// The handles the WebSocket check sequence runs on. Every handle is
/// optional: an absent handle skips its arm, and the sequence stays
/// infallible (the engine's ban, gate, limiter, and scan primitives report
/// through plain values, so the reference's Redis failure branches have no
/// counterpart here).
#[derive(Clone)]
pub struct WebSocketGuardConfig {
    detect_config: DetectConfig,
    ip_gate: Option<IpGateConfig>,
    ban_manager: Option<IpBanManager>,
    rate_limiter: Option<RateLimiter>,
    country_rules: Option<(CountryGate, Arc<dyn GeoIpHandler>)>,
    violation_feed: Option<ViolationFeed>,
    fail_secure: bool,
    exclusions: ResolvedExclusions,
}

/// Manual [`core::fmt::Debug`]: the geo handler is a trait object without
/// `Debug`, so the config prints its shape and stops
/// (`finish_non_exhaustive`), the family's `BanState` convention.
impl core::fmt::Debug for WebSocketGuardConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WebSocketGuardConfig")
            .field("detect_config", &self.detect_config)
            .field("ip_gate", &self.ip_gate)
            .field("ban_manager", &self.ban_manager)
            .field("rate_limiter", &self.rate_limiter)
            .field("violation_feed", &self.violation_feed)
            .field("fail_secure", &self.fail_secure)
            .field("exclusions", &self.exclusions)
            .finish_non_exhaustive()
    }
}

impl WebSocketGuardConfig {
    /// A config with no handles: only the penetration scan runs, and an
    /// unattributable upgrade passes (fail-open, the reference default).
    #[must_use]
    pub fn new(detect_config: DetectConfig) -> Self {
        Self {
            detect_config,
            ip_gate: None,
            ban_manager: None,
            rate_limiter: None,
            country_rules: None,
            violation_feed: None,
            fail_secure: false,
            exclusions: resolve_exclusions(None, None),
        }
    }

    /// Install the global IP gate (`whitelist`/`blacklist`/`exempt_ips`)
    /// the `is_ip_allowed` list arms evaluate.
    #[must_use]
    pub fn with_ip_gate(mut self, ip_gate: IpGateConfig) -> Self {
        self.ip_gate = Some(ip_gate);
        self
    }

    /// Install the ban manager the `is_ip_banned` arm consults (and the
    /// violation feed's auto-ban applies through).
    #[must_use]
    pub fn with_ip_banning(mut self, ban_manager: IpBanManager) -> Self {
        self.ban_manager = Some(ban_manager);
        self
    }

    /// Install the rate limiter the `check_rate_limit_by_ip` arm records
    /// through (the `ws` endpoint key, the reference's `endpoint_path`).
    #[must_use]
    pub fn with_rate_limiting(mut self, rate_limiter: RateLimiter) -> Self {
        self.rate_limiter = Some(rate_limiter);
        self
    }

    /// Install the country rules (`whitelist_countries`/`blocked_countries`
    /// resolved through [`parse_country_lists`](guard_core_engine::geo::parse_country_lists))
    /// and the [`GeoIpHandler`] they resolve countries through.
    #[must_use]
    pub fn with_country_rules(mut self, gate: CountryGate, handler: Arc<dyn GeoIpHandler>) -> Self {
        self.country_rules = Some((gate, handler));
        self
    }

    /// Install the shared violation feed (the reference's shared
    /// `suspicious_request_counts`): every detection - handshake scan and
    /// frame scan - records into `feed`'s store, and a crossed threshold
    /// bans the address through the installed [`IpBanManager`].
    #[must_use]
    pub fn with_violation_feed(mut self, feed: ViolationFeed) -> Self {
        self.violation_feed = Some(feed);
        self
    }

    /// Fail the handshake closed when the client address cannot be
    /// determined (the reference `fail_secure` arm).
    #[must_use]
    pub const fn with_fail_secure(mut self, fail_secure: bool) -> Self {
        self.fail_secure = fail_secure;
        self
    }

    /// Install global detection exclusions for the scan arms (the header
    /// set merges over the engine defaults; every other surface overrides).
    #[must_use]
    pub fn with_detection_exclusions(
        mut self,
        detection_exclusions: &DetectionExclusionConfig,
    ) -> Self {
        self.exclusions = resolve_exclusions(Some(detection_exclusions), None);
        self
    }
}

/// The reference check sequence (`_run_websocket_checks`): ban arm, the
/// `is_ip_allowed` family, the `ws` rate limit, then the penetration scan
/// over path, query, and headers (an upgrade carries no body). A flagged
/// scan also feeds the shared violation store
/// ([`WebSocketGuardConfig::with_violation_feed`]), exactly like the
/// reference's shared suspicious counts.
///
/// # Errors
///
/// The close shape the handshake must be rejected with. Unattributable
/// requests (`client_ip` absent) skip the stateful arms - there is no
/// identity to ban, gate, limit, or count - and stay detection-screened;
/// under [`WebSocketGuardConfig::with_fail_secure`] they are rejected
/// outright.
pub fn run_websocket_checks(
    config: &WebSocketGuardConfig,
    client_ip: Option<IpAddr>,
    url_path: &str,
    query_params: &[(String, String)],
    headers: &[(String, String)],
) -> Result<(), WebSocketCloseReason> {
    if client_ip.is_none() && config.fail_secure {
        return Err(WS_CLOSE_CLIENT_ADDRESS_UNKNOWN);
    }

    if let (Some(manager), Some(ip)) = (&config.ban_manager, client_ip)
        && manager.is_banned(ip)
    {
        return Err(WS_CLOSE_IP_BANNED);
    }

    let mut whitelisted = false;
    if let (Some(gate), Some(ip)) = (&config.ip_gate, client_ip) {
        match gate.evaluate(ip) {
            IpGateVerdict::Denied(_) => return Err(WS_CLOSE_IP_NOT_ALLOWED),
            IpGateVerdict::Allowed(decision) => whitelisted = decision.is_whitelisted,
        }
    }

    if let (Some((gate, handler)), Some(ip)) = (&config.country_rules, client_ip)
        && check_countries(ip, gate, handler.as_ref(), whitelisted).is_some()
    {
        return Err(WS_CLOSE_IP_NOT_ALLOWED);
    }

    if let (Some(limiter), Some(ip)) = (&config.rate_limiter, client_ip)
        && !whitelisted
        && !limiter.check(ip, Some("ws")).allowed
    {
        return Err(WS_CLOSE_RATE_LIMIT_EXCEEDED);
    }

    let surfaces = RequestSurfaces {
        url_path: Some(url_path),
        query_params,
        headers,
        content_type: "",
        raw_body: "",
    };
    let verdict = scan_request(&surfaces, &config.exclusions, &config.detect_config);
    if verdict.is_threat {
        feed_violations(config, client_ip, &verdict);
        return Err(WS_CLOSE_SUSPICIOUS_ACTIVITY);
    }
    Ok(())
}

/// Record a flagged scan into the shared violation store (the reference's
/// shared suspicious counts): every category counts, and a crossed
/// threshold bans the address through the installed [`IpBanManager`]. No
/// feed installed, no identity, or no ban manager reduces to counting (or
/// nothing).
fn feed_violations(
    config: &WebSocketGuardConfig,
    client_ip: Option<IpAddr>,
    verdict: &RequestScanVerdict,
) {
    let (Some(feed), Some(ip)) = (config.violation_feed.as_ref(), client_ip) else {
        return;
    };
    let categories: Vec<&str> = verdict.categories.iter().map(String::as_str).collect();
    let reason = format!("Suspicious activity detected: {ip}");
    match config.ban_manager.as_ref() {
        Some(manager) => {
            let _ = manager.register_violations(
                &feed.counters,
                ip,
                &categories,
                &feed.ban_config,
                &reason,
            );
        }
        None => feed.counters.record(ip, &categories),
    }
}

/// [`run_websocket_checks`] (or a frame scan) contained: a panic anywhere in
/// the sequence (an injected [`GeoIpHandler`], a foreign handle) maps to the
/// reference's engine-malfunction close shape, `1013 Try again later`.
fn run_guarded(
    checks: impl FnOnce() -> Result<(), WebSocketCloseReason>,
) -> Result<(), WebSocketCloseReason> {
    catch_unwind(AssertUnwindSafe(checks)).unwrap_or(Err(WS_CLOSE_SECURITY_CHECK_FAILED))
}

/// The `parse_qsl`-decoded query pairs (`+` is a space, percent escapes
/// decode, a malformed escape stays literal): the family's query surface.
fn parse_query_pairs(raw_query: &str) -> Vec<(String, String)> {
    if raw_query.is_empty() {
        return Vec::new();
    }
    raw_query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((name, value)) => (decode_component(name), decode_component(value)),
            None => (decode_component(pair), String::new()),
        })
        .collect()
}

fn decode_component(component: &str) -> String {
    let bytes = component.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if bytes.len() >= index + 3 => {
                let high = (bytes[index + 1] as char).to_digit(16);
                let low = (bytes[index + 2] as char).to_digit(16);
                if let (Some(high), Some(low)) = (high, low) {
                    out.push(u8::try_from(high * 16 + low).unwrap_or(b'%'));
                    index += 3;
                } else {
                    out.push(b'%');
                    index += 1;
                }
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The installed WebSocket guard: [`make_guard_websocket`]'s return value.
///
/// Manage it on the application
/// (`rocket.build().manage(make_guard_websocket(config))` - the reference
/// discovers its config through the app the same way) and declare it as a
/// request guard on the `rocket_ws` routes it protects. The guard outcome
/// carries the close shape a rejection must render; wrap the argument in
/// `Result` to capture it and answer through [`WsGuardError`], the
/// pre-accept `403` responder.
#[derive(Clone)]
pub struct WebSocketGuard {
    config: Arc<WebSocketGuardConfig>,
}

/// The rejected-handshake responder: `403 Forbidden` pre-accept, the close
/// shape on [`WS_CLOSE_CODE_HEADER`] / [`WS_CLOSE_REASON_HEADER`], and the
/// family's plain-text body naming the reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WsGuardError {
    /// The close shape the rejection renders.
    pub reason: WebSocketCloseReason,
}

impl WsGuardError {
    /// Wrap a close shape for the rejection response.
    #[must_use]
    pub const fn new(reason: WebSocketCloseReason) -> Self {
        Self { reason }
    }
}

impl<'r, 'o: 'r> Responder<'r, 'o> for WsGuardError {
    fn respond_to(self, _: &'r Request<'_>) -> response::Result<'o> {
        let body = format!("WebSocket connection rejected: {}", self.reason.reason);
        rocket::Response::build()
            .status(Status::Forbidden)
            .raw_header(WS_CLOSE_CODE_HEADER, self.reason.code.to_string())
            .raw_header(WS_CLOSE_REASON_HEADER, self.reason.reason)
            .header(rocket::http::ContentType::Plain)
            .sized_body(body.len(), Cursor::new(body))
            .ok()
    }
}

/// The guard's `FromRequest` shape: resolve the managed
/// [`WebSocketGuard`], run the reference sequence over the request, and
/// succeed, or fail with the [`WsGuardError`] the route renders.
#[rocket::async_trait]
impl<'r> FromRequest<'r> for WebSocketGuard {
    type Error = WsGuardError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let Some(guard) = request.rocket().state::<WebSocketGuard>() else {
            return Outcome::Error((
                Status::Forbidden,
                WsGuardError::new(WS_CLOSE_SECURITY_CHECK_FAILED),
            ));
        };
        match guard.upgrade_verdict(request) {
            Ok(()) => Outcome::Success(guard.clone()),
            Err(reason) => Outcome::Error((Status::Forbidden, WsGuardError::new(reason))),
        }
    }
}

impl WebSocketGuard {
    /// Build the guard from its handles - the reference
    /// `make_guard_websocket(config, redis_handler)` (the engine primitives
    /// are infallible, so the Redis-failure argument has no Rust
    /// counterpart; the distributed stores ride the handles themselves).
    #[must_use]
    pub fn new(config: WebSocketGuardConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    /// The reference check sequence over raw views (the programmatic seam:
    /// the same sequence the request guard runs). `Err` carries the close
    /// shape the handshake must be rejected with.
    ///
    /// # Errors
    ///
    /// The reference's close shapes; a panic in the sequence (an injected
    /// [`GeoIpHandler`], a foreign handle) maps to
    /// [`WS_CLOSE_SECURITY_CHECK_FAILED`].
    pub fn upgrade_verdict(&self, request: &Request<'_>) -> Result<(), WebSocketCloseReason> {
        let client_ip = request.client_ip();
        let url_path = request.uri().path().as_str().to_owned();
        let query_params =
            parse_query_pairs(request.uri().query().map_or("", |query| query.as_str()));
        let headers: Vec<(String, String)> = request
            .headers()
            .iter()
            .map(|header| (header.name().as_str().to_owned(), header.value().to_owned()))
            .collect();
        run_guarded(|| {
            run_websocket_checks(&self.config, client_ip, &url_path, &query_params, &headers)
        })
    }

    /// The per-frame guard (the reference detection callable at frame
    /// granularity): text and binary payloads scan through the engine's
    /// body view, a threat feeds the shared violation store, and `Err`
    /// carries the close shape the channel must answer with (answer with
    /// [`WebSocketGuard::close_frame`] +
    /// [`WebSocketGuard::stream_error`], or your own Close frame).
    /// Control frames (`Ping`/`Pong`/`Close`/raw `Frame`) pass untouched.
    ///
    /// `client_ip` is the connection's identity for the stateful arms;
    /// `None` skips them (fail-open), matching the handshake sequence.
    ///
    /// # Errors
    ///
    /// [`WS_CLOSE_SUSPICIOUS_ACTIVITY`] on a flagged payload,
    /// [`WS_CLOSE_SECURITY_CHECK_FAILED`] when the scan panics.
    pub fn scan_frame(
        &self,
        client_ip: Option<IpAddr>,
        message: &Message,
    ) -> Result<(), WebSocketCloseReason> {
        let payload: String = match message {
            Message::Text(text) => text.clone(),
            Message::Binary(bytes) => String::from_utf8_lossy(bytes).into_owned(),
            Message::Ping(_) | Message::Pong(_) | Message::Close(_) | Message::Frame(_) => {
                return Ok(());
            }
        };
        run_guarded(|| self.scan_payload(client_ip, &payload))
    }

    /// The body-view scan one frame runs (a frame carries no path, query,
    /// or headers of its own).
    fn scan_payload(
        &self,
        client_ip: Option<IpAddr>,
        payload: &str,
    ) -> Result<(), WebSocketCloseReason> {
        let empty: Vec<(String, String)> = Vec::new();
        let surfaces = RequestSurfaces {
            url_path: None,
            query_params: &empty,
            headers: &empty,
            content_type: "",
            raw_body: payload,
        };
        let verdict = scan_request(
            &surfaces,
            &self.config.exclusions,
            &self.config.detect_config,
        );
        if verdict.is_threat {
            feed_violations(&self.config, client_ip, &verdict);
            return Err(WS_CLOSE_SUSPICIOUS_ACTIVITY);
        }
        Ok(())
    }

    /// The close frame answering a rejected frame: the reference's close
    /// shape, verbatim (`1008 Policy Violation` policy denials,
    /// `1013 Try Again Later` malfunctions).
    #[must_use]
    pub fn close_frame(reason: WebSocketCloseReason) -> Message {
        Message::Close(Some(CloseFrame {
            code: CloseCode::from(reason.code),
            reason: Cow::Borrowed(reason.reason),
        }))
    }

    /// The channel-loop error ending a rejected frame's connection: the
    /// close shape as a `rocket_ws` I/O error (the loop already sent
    /// [`WebSocketGuard::close_frame`]; this ends it).
    #[must_use]
    pub fn stream_error(reason: WebSocketCloseReason) -> rocket_ws::result::Error {
        rocket_ws::result::Error::Io(std::io::Error::other(format!(
            "{text} ({code})",
            text = reason.reason,
            code = reason.code
        )))
    }
}

/// A [`WebSocketGuard`], in the reference's own name:
/// `make_guard_websocket(config, redis_handler)`. Manage the return value
/// and declare the guard on the `rocket_ws` routes it protects (see
/// [`WebSocketGuard`]).
#[must_use]
pub fn make_guard_websocket(config: WebSocketGuardConfig) -> WebSocketGuard {
    WebSocketGuard::new(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use guard_core_engine::geo::parse_country_lists;
    use guard_core_engine::ip_gate::IpGateDecision;
    use guard_core_engine::rate_limit::RateLimitConfig;
    use rocket::http::Header;
    use rocket::local::asynchronous::{Client, LocalResponse};
    use rocket::{get, routes};
    use std::net::SocketAddr;

    fn detect_config() -> DetectConfig {
        crate::default_config()
    }

    /// The close shape a rendered message carries, if any (the test view of
    /// [`WebSocketGuard::close_frame`]).
    fn close_parts(message: &Message) -> Option<Vec<(u16, &str)>> {
        match message {
            Message::Close(Some(frame)) => {
                Some(vec![(u16::from(frame.code), frame.reason.as_ref())])
            }
            _ => None,
        }
    }

    fn ip(literal: &str) -> IpAddr {
        literal.parse().expect("ip")
    }

    fn peer(octets: [u8; 4]) -> SocketAddr {
        SocketAddr::from((octets, 45_000))
    }

    #[test]
    fn close_table_matches_the_reference() {
        assert_eq!(
            WS_CLOSE_IP_BANNED,
            WebSocketCloseReason {
                code: 1008,
                reason: "IP banned"
            }
        );
        assert_eq!(
            WS_CLOSE_IP_NOT_ALLOWED,
            WebSocketCloseReason {
                code: 1008,
                reason: "IP not allowed"
            }
        );
        assert_eq!(
            WS_CLOSE_RATE_LIMIT_EXCEEDED,
            WebSocketCloseReason {
                code: 1008,
                reason: "Rate limit exceeded"
            }
        );
        assert_eq!(
            WS_CLOSE_CLIENT_ADDRESS_UNKNOWN,
            WebSocketCloseReason {
                code: 1008,
                reason: "Client address could not be determined"
            }
        );
        assert_eq!(
            WS_CLOSE_SECURITY_CHECK_FAILED,
            WebSocketCloseReason {
                code: 1013,
                reason: "Security check failed"
            }
        );
        assert_eq!(
            WS_CLOSE_SUSPICIOUS_ACTIVITY,
            WebSocketCloseReason {
                code: 1008,
                reason: "Suspicious activity detected"
            }
        );
    }

    fn upgrade_headers() -> HeaderMap<'static> {
        let mut headers = HeaderMap::new();
        headers.add(Header::new("Connection", "keep-alive, Upgrade"));
        headers.add(Header::new("Upgrade", "WebSocket"));
        headers
    }

    #[test]
    fn upgrade_detection_reads_both_headers() {
        assert!(is_websocket_upgrade(&upgrade_headers()));

        let mut plain = HeaderMap::new();
        plain.add(Header::new("Connection", "keep-alive"));
        plain.add(Header::new("Upgrade", "websocket"));
        assert!(!is_websocket_upgrade(&plain));

        let mut no_upgrade = HeaderMap::new();
        no_upgrade.add(Header::new("Connection", "upgrade"));
        no_upgrade.add(Header::new("Upgrade", "h2c"));
        assert!(!is_websocket_upgrade(&no_upgrade));

        let empty = HeaderMap::new();
        assert!(!is_websocket_upgrade(&empty));
    }

    #[test]
    fn query_pairs_decode_like_parse_qsl() {
        assert_eq!(
            parse_query_pairs("q=%3Cscript%3E&x=a+b&flag&bad=%zz"),
            vec![
                (String::from("q"), String::from("<script>")),
                (String::from("x"), String::from("a b")),
                (String::from("flag"), String::new()),
                (String::from("bad"), String::from("%zz")),
            ]
        );
        assert_eq!(parse_query_pairs(""), Vec::<(String, String)>::new());
        assert_eq!(decode_component("caf%C3%A9"), "café");
        assert_eq!(decode_component("abc"), "abc");
    }

    #[test]
    fn clean_upgrade_passes_every_arm() {
        let config = WebSocketGuardConfig::new(detect_config());
        assert_eq!(
            run_websocket_checks(&config, Some(ip("203.0.113.7")), "/ws", &[], &[]),
            Ok(())
        );
    }

    #[test]
    fn unknown_address_is_fail_open_by_default_and_fail_secure_on_request() {
        let config = WebSocketGuardConfig::new(detect_config());
        assert_eq!(run_websocket_checks(&config, None, "/ws", &[], &[]), Ok(()));
        let config = config.with_fail_secure(true);
        assert_eq!(
            run_websocket_checks(&config, None, "/ws", &[], &[]),
            Err(WS_CLOSE_CLIENT_ADDRESS_UNKNOWN)
        );
    }

    #[test]
    fn ban_arm_answers_ip_banned() {
        let manager = IpBanManager::new();
        let banned = ip("203.0.113.9");
        manager.ban_ip(banned, 60, "test ban").expect("ban");
        let config = WebSocketGuardConfig::new(detect_config()).with_ip_banning(manager);
        assert_eq!(
            run_websocket_checks(&config, Some(banned), "/ws", &[], &[]),
            Err(WS_CLOSE_IP_BANNED)
        );
    }

    #[test]
    fn gate_lists_answer_ip_not_allowed() {
        let blacklist = IpGateConfig::new([] as [&str; 0], ["203.0.113.0/24"], [] as [&str; 0])
            .expect("valid lists");
        let config = WebSocketGuardConfig::new(detect_config()).with_ip_gate(blacklist);
        assert_eq!(
            run_websocket_checks(&config, Some(ip("203.0.113.9")), "/ws", &[], &[]),
            Err(WS_CLOSE_IP_NOT_ALLOWED)
        );

        let whitelist = IpGateConfig::new(
            ["198.51.100.0/24"] as [&str; 1],
            [] as [&str; 0],
            [] as [&str; 0],
        )
        .expect("valid lists");
        let config = WebSocketGuardConfig::new(detect_config()).with_ip_gate(whitelist);
        assert_eq!(
            run_websocket_checks(&config, Some(ip("203.0.113.9")), "/ws", &[], &[]),
            Err(WS_CLOSE_IP_NOT_ALLOWED)
        );
        assert_eq!(
            run_websocket_checks(&config, Some(ip("198.51.100.4")), "/ws", &[], &[]),
            Ok(())
        );
    }

    struct FixedCountry(&'static str);

    impl GeoIpHandler for FixedCountry {
        fn get_country(&self, _ip: IpAddr) -> Option<String> {
            Some(self.0.to_owned())
        }
    }

    #[test]
    fn country_rules_answer_ip_not_allowed_and_whitelist_skips_them() {
        let gate = parse_country_lists(["US"], [] as [&str; 0]);
        let config = WebSocketGuardConfig::new(detect_config())
            .with_country_rules(gate, Arc::new(FixedCountry("DE")));
        assert_eq!(
            run_websocket_checks(&config, Some(ip("203.0.113.9")), "/ws", &[], &[]),
            Err(WS_CLOSE_IP_NOT_ALLOWED)
        );

        let allowed = ip("203.0.113.9");
        let whitelist = IpGateConfig::new([allowed.to_string()], [] as [&str; 0], [] as [&str; 0])
            .expect("valid lists");
        let country = parse_country_lists(["US"], [] as [&str; 0]);
        let config = WebSocketGuardConfig::new(detect_config())
            .with_ip_gate(whitelist)
            .with_country_rules(country, Arc::new(FixedCountry("DE")));
        assert_eq!(
            run_websocket_checks(&config, Some(allowed), "/ws", &[], &[]),
            Ok(())
        );
    }

    #[test]
    fn rate_limit_arm_answers_rate_limit_exceeded_and_skips_whitelisted() {
        let limiter = RateLimiter::new(RateLimitConfig {
            enable_rate_limiting: true,
            rate_limit: 1,
            rate_limit_window: 10,
            ..RateLimitConfig::default()
        })
        .expect("valid config");
        let config = WebSocketGuardConfig::new(detect_config()).with_rate_limiting(limiter);
        let client = ip("203.0.113.9");
        assert_eq!(
            run_websocket_checks(&config, Some(client), "/ws", &[], &[]),
            Ok(())
        );
        assert_eq!(
            run_websocket_checks(&config, Some(client), "/ws", &[], &[]),
            Err(WS_CLOSE_RATE_LIMIT_EXCEEDED)
        );

        let whitelist = IpGateConfig::new([client.to_string()], [] as [&str; 0], [] as [&str; 0])
            .expect("valid lists");
        let limiter = RateLimiter::new(RateLimitConfig {
            enable_rate_limiting: true,
            rate_limit: 1,
            rate_limit_window: 10,
            ..RateLimitConfig::default()
        })
        .expect("valid config");
        let config = WebSocketGuardConfig::new(detect_config())
            .with_ip_gate(whitelist)
            .with_rate_limiting(limiter);
        assert_eq!(
            run_websocket_checks(&config, Some(client), "/ws", &[], &[]),
            Ok(())
        );
        assert_eq!(
            run_websocket_checks(&config, Some(client), "/ws", &[], &[]),
            Ok(())
        );
    }

    #[test]
    fn scan_arm_answers_suspicious_activity() {
        let config = WebSocketGuardConfig::new(detect_config());
        let client = ip("203.0.113.9");
        assert_eq!(
            run_websocket_checks(&config, Some(client), "/etc/passwd", &[], &[]),
            Err(WS_CLOSE_SUSPICIOUS_ACTIVITY)
        );
        assert_eq!(
            run_websocket_checks(
                &config,
                Some(client),
                "/ws",
                &[("cmd".to_owned(), String::from("$(whoami)"))],
                &[],
            ),
            Err(WS_CLOSE_SUSPICIOUS_ACTIVITY)
        );
        assert_eq!(
            run_websocket_checks(
                &config,
                Some(client),
                "/ws",
                &[],
                &[(
                    "x-inject".to_owned(),
                    String::from("<script>alert(1)</script>")
                )],
            ),
            Err(WS_CLOSE_SUSPICIOUS_ACTIVITY)
        );
    }

    #[test]
    fn detection_exclusions_shape_the_scan_arm() {
        let exclusions = DetectionExclusionConfig {
            excluded_detection_params: vec!["secret".to_owned()],
            ..DetectionExclusionConfig::default()
        };
        let config =
            WebSocketGuardConfig::new(detect_config()).with_detection_exclusions(&exclusions);
        let client = ip("203.0.113.9");
        // The excluded param name skips the scan entirely.
        assert_eq!(
            run_websocket_checks(
                &config,
                Some(client),
                "/ws",
                &[(
                    "secret".to_owned(),
                    String::from("<script>alert(1)</script>")
                )],
                &[],
            ),
            Ok(())
        );
        // Any other name scans.
        assert_eq!(
            run_websocket_checks(
                &config,
                Some(client),
                "/ws",
                &[(
                    "public".to_owned(),
                    String::from("<script>alert(1)</script>")
                )],
                &[],
            ),
            Err(WS_CLOSE_SUSPICIOUS_ACTIVITY)
        );
    }

    #[test]
    fn check_panic_maps_to_try_again_later() {
        // The 1013 shape is reachable through exactly the reference's
        // remaining arm: the check machinery panicking mid-sequence (an
        // injected GeoIpHandler, a foreign handle). The containment maps
        // every panic to the engine-malfunction close.
        assert_eq!(
            run_guarded(|| panic!("geo backend down")),
            Err(WS_CLOSE_SECURITY_CHECK_FAILED)
        );
        assert_eq!(run_guarded(|| Ok(())), Ok(()));
    }

    #[test]
    fn debug_prints_the_config_shape() {
        let feed = ViolationFeed::new(ViolationCounters::new(), IpBanConfig::default());
        let config = WebSocketGuardConfig::new(detect_config())
            .with_fail_secure(true)
            .with_violation_feed(feed.clone());
        let printed = format!("{config:?}");
        assert!(
            printed.starts_with("WebSocketGuardConfig"),
            "the debug shape names the config: {printed}"
        );
        assert!(printed.contains("fail_secure: true"), "{printed}");
        assert!(printed.contains("violation_feed"), "{printed}");
        assert!(format!("{:?}", feed.counters()).contains("ViolationCounters"),);
    }

    #[test]
    fn violation_feed_shares_counts_and_bans_across_consumers() {
        // The shared-suspicious-counts contract: one store cloned into two
        // feeds counts together, and the auto-ban the feed resolves lands
        // in the shared ban manager.
        let counters = ViolationCounters::new();
        let ban_config = IpBanConfig {
            enable_ip_banning: true,
            auto_ban_threshold: 2,
            auto_ban_duration: 60,
            ..IpBanConfig::default()
        };
        ban_config.validate().expect("valid ban config");
        let feed = ViolationFeed::new(counters.clone(), ban_config.clone());
        let manager = IpBanManager::new();
        let client = ip("203.0.113.9");
        let verdict = RequestScanVerdict {
            is_threat: true,
            categories: vec![String::from("sqli")],
            reason: String::from("sqli"),
        };

        // Frame 1: counts, below the threshold, connection closes with the
        // suspicious-activity shape - the reference's single detection arm.
        let config = WebSocketGuardConfig::new(detect_config())
            .with_ip_banning(manager.clone())
            .with_violation_feed(feed.clone());
        feed_violations(&config, Some(client), &verdict);
        assert!(!manager.is_banned(client));
        assert_eq!(feed.counters().snapshot(client).get("sqli"), Some(&1));

        // Frame 2 (the same store through a second clone): the threshold
        // crosses and the ban lands in the shared manager.
        feed_violations(&config, Some(client), &verdict);
        assert!(manager.is_banned(client));
        assert_eq!(feed.counters().snapshot(client).get("sqli"), Some(&2));

        // The next handshake's ban arm rejects the address.
        assert_eq!(
            run_websocket_checks(&config, Some(client), "/ws", &[], &[]),
            Err(WS_CLOSE_IP_BANNED)
        );

        // Counting without a ban manager: the store still records.
        let feed = ViolationFeed::new(ViolationCounters::new(), ban_config.clone());
        let config = WebSocketGuardConfig::new(detect_config()).with_violation_feed(feed.clone());
        feed_violations(&config, Some(client), &verdict);
        assert_eq!(feed.counters().snapshot(client).get("sqli"), Some(&1));

        // No feed, no identity: nothing records anywhere.
        let plain = WebSocketGuardConfig::new(detect_config());
        feed_violations(&plain, Some(client), &verdict);
        feed_violations(&config, None, &verdict);
    }

    #[test]
    fn scan_frame_scans_payloads_and_passes_control_frames() {
        let config = WebSocketGuardConfig::new(detect_config());
        let guard = WebSocketGuard::new(config);
        let client = ip("203.0.113.9");

        // A clean text frame passes.
        assert_eq!(
            guard.scan_frame(Some(client), &Message::text("hello")),
            Ok(())
        );
        // A clean binary frame passes.
        assert_eq!(
            guard.scan_frame(Some(client), &Message::binary([1u8, 2, 3])),
            Ok(())
        );
        // Control frames pass untouched.
        assert_eq!(
            guard.scan_frame(Some(client), &Message::Ping(vec![b'p'])),
            Ok(())
        );
        assert_eq!(
            guard.scan_frame(Some(client), &Message::Pong(vec![b'p'])),
            Ok(())
        );
        assert_eq!(
            guard.scan_frame(Some(client), &Message::Close(None)),
            Ok(())
        );
        assert_eq!(
            guard.scan_frame(
                Some(client),
                &Message::Frame(rocket_ws::frame::Frame::ping(Vec::new()))
            ),
            Ok(())
        );

        // A threat in a text frame closes with the suspicious-activity
        // shape; a threat in a binary frame does the same.
        assert_eq!(
            guard.scan_frame(Some(client), &Message::text("'; DROP TABLE users; --")),
            Err(WS_CLOSE_SUSPICIOUS_ACTIVITY)
        );
        assert_eq!(
            guard.scan_frame(Some(client), &Message::binary("<script>alert(1)</script>")),
            Err(WS_CLOSE_SUSPICIOUS_ACTIVITY)
        );

        // A non-UTF-8 binary frame scans its lossy rendering.
        assert_eq!(
            guard.scan_frame(Some(client), &Message::binary([0xffu8, 0xfe])),
            Ok(())
        );
    }

    #[test]
    fn frame_threats_feed_the_shared_violation_store() {
        let ban_config = IpBanConfig {
            enable_ip_banning: true,
            auto_ban_threshold: 1,
            auto_ban_duration: 60,
            ..IpBanConfig::default()
        };
        ban_config.validate().expect("valid ban config");
        let manager = IpBanManager::new();
        let config = WebSocketGuardConfig::new(detect_config())
            .with_ip_banning(manager.clone())
            .with_violation_feed(ViolationFeed::new(ViolationCounters::new(), ban_config));
        let guard = WebSocketGuard::new(config);
        let client = ip("203.0.113.9");

        // The first flagged frame closes the connection with the reference
        // close arm AND lands its auto-ban (threshold 1).
        assert_eq!(
            guard.scan_frame(Some(client), &Message::text("<script>alert(1)</script>")),
            Err(WS_CLOSE_SUSPICIOUS_ACTIVITY)
        );
        assert!(manager.is_banned(client));
    }

    #[test]
    fn close_frame_and_stream_error_carry_the_shape() {
        assert_eq!(
            close_parts(&WebSocketGuard::close_frame(WS_CLOSE_IP_BANNED)).as_deref(),
            Some([(1008u16, "IP banned")].as_slice())
        );
        assert_eq!(
            close_parts(&WebSocketGuard::close_frame(WS_CLOSE_SECURITY_CHECK_FAILED)).as_deref(),
            Some([(1013u16, "Security check failed")].as_slice())
        );
        // Every arm of the extractor is exercised: control shapes yield no
        // close parts.
        assert_eq!(close_parts(&Message::text("hello")), None);
        assert_eq!(close_parts(&Message::Close(None)), None);

        let error = WebSocketGuard::stream_error(WS_CLOSE_SUSPICIOUS_ACTIVITY);
        let rendered = error.to_string();
        assert!(
            rendered.contains("Suspicious activity detected"),
            "{rendered}"
        );
        assert!(rendered.contains("1008"), "{rendered}");
    }

    // The request-guard lanes, driven through a real Rocket instance: the
    // probe route captures the guard outcome so both arms render.

    async fn probe_client(guard: WebSocketGuard) -> Client {
        Client::tracked(
            rocket::build()
                .manage(guard)
                .mount("/", routes![probe, flagged]),
        )
        .await
        .expect("valid rocket")
    }

    // The probe route renders the captured guard outcome as text (the clean
    // path exercises the Ok arm). The traversal-shaped second route lets the
    // end-to-end tests drive the scan arm against a matched route.
    #[get("/probe")]
    #[allow(clippy::needless_pass_by_value)] // rocket guard extraction hands the value
    fn probe(guard: Result<WebSocketGuard, WsGuardError>) -> String {
        outcome_text(guard)
    }

    #[get("/etc/passwd")]
    #[allow(clippy::needless_pass_by_value)] // rocket guard extraction hands the value
    fn flagged(guard: Result<WebSocketGuard, WsGuardError>) -> String {
        outcome_text(guard)
    }

    #[allow(clippy::needless_pass_by_value)] // rocket guard extraction hands the value
    fn outcome_text(guard: Result<WebSocketGuard, WsGuardError>) -> String {
        match guard {
            Ok(_) => String::from("granted"),
            Err(error) => {
                let code = error.reason.code;
                let reason = error.reason.reason;
                format!("{code} {reason}")
            }
        }
    }

    async fn body_of(response: LocalResponse<'_>) -> String {
        response.into_string().await.unwrap_or_default()
    }

    #[tokio::test]
    async fn clean_upgrade_is_granted_through_the_guard() {
        let client = probe_client(make_guard_websocket(WebSocketGuardConfig::new(
            detect_config(),
        )))
        .await;
        let response = client
            .get("/probe")
            .remote(peer([203, 0, 113, 7]))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(body_of(response).await, "granted");
    }

    #[tokio::test]
    async fn banned_client_is_denied_with_the_close_shape() {
        let manager = IpBanManager::new();
        manager
            .ban_ip(ip("203.0.113.9"), 60, "test ban")
            .expect("ban");
        let client = probe_client(make_guard_websocket(
            WebSocketGuardConfig::new(detect_config()).with_ip_banning(manager),
        ))
        .await;
        let response = client
            .get("/probe")
            .remote(peer([203, 0, 113, 9]))
            .dispatch()
            .await;
        // The probe route renders the captured outcome as text; the
        // pre-accept 403 + headers rendering is pinned by
        // `rejection_renders_the_close_headers` through the reject route.
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(body_of(response).await, "1008 IP banned");
    }

    #[tokio::test]
    async fn rejection_renders_the_close_headers() {
        let manager = IpBanManager::new();
        manager
            .ban_ip(ip("203.0.113.9"), 60, "test ban")
            .expect("ban");
        let client = Client::tracked(
            rocket::build()
                .manage(make_guard_websocket(
                    WebSocketGuardConfig::new(detect_config()).with_ip_banning(manager),
                ))
                .mount("/", routes![reject]),
        )
        .await
        .expect("valid rocket");
        let response = client
            .get("/reject")
            .remote(peer([203, 0, 113, 9]))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Forbidden);
        assert_eq!(
            response
                .headers()
                .get_one(WS_CLOSE_CODE_HEADER)
                .map(str::to_owned),
            Some(String::from("1008"))
        );
        assert_eq!(
            response
                .headers()
                .get_one(WS_CLOSE_REASON_HEADER)
                .map(str::to_owned),
            Some(String::from("IP banned"))
        );
        assert_eq!(
            response
                .headers()
                .get_one("Content-Type")
                .map(str::to_owned),
            Some(String::from("text/plain; charset=utf-8"))
        );
        assert_eq!(
            body_of(response).await,
            "WebSocket connection rejected: IP banned"
        );
    }

    #[get("/reject")]
    #[allow(clippy::needless_pass_by_value)] // rocket guard extraction hands the value
    fn reject(guard: Result<WebSocketGuard, WsGuardError>) -> Result<&'static str, WsGuardError> {
        guard.map(|_| "granted")
    }

    #[tokio::test]
    async fn unknown_address_fail_secure_denies_the_handshake() {
        let client = probe_client(make_guard_websocket(
            WebSocketGuardConfig::new(detect_config()).with_fail_secure(true),
        ))
        .await;
        // A local dispatch with no remote set carries no client IP.
        let response = client.get("/probe").dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(
            body_of(response).await,
            "1008 Client address could not be determined"
        );
    }

    #[tokio::test]
    async fn missing_managed_state_is_an_engine_malfunction() {
        let client = Client::tracked(rocket::build().mount("/", routes![probe]))
            .await
            .expect("valid rocket");
        let response = client.get("/probe").dispatch().await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(body_of(response).await, "1013 Security check failed");
    }

    #[tokio::test]
    async fn handshake_scan_feeds_the_shared_counts_end_to_end() {
        let ban_config = IpBanConfig {
            enable_ip_banning: true,
            auto_ban_threshold: 1,
            auto_ban_duration: 60,
            ..IpBanConfig::default()
        };
        ban_config.validate().expect("valid ban config");
        let manager = IpBanManager::new();
        let feed = ViolationFeed::new(ViolationCounters::new(), ban_config);
        let client = probe_client(make_guard_websocket(
            WebSocketGuardConfig::new(detect_config())
                .with_ip_banning(manager.clone())
                .with_violation_feed(feed.clone()),
        ))
        .await;

        // Handshake 1: the path scan flags, the connection closes with the
        // suspicious shape, and the auto-ban lands in the shared manager.
        let response = client
            .get("/etc/passwd")
            .remote(peer([203, 0, 113, 9]))
            .dispatch()
            .await;
        assert_eq!(body_of(response).await, "1008 Suspicious activity detected");
        assert!(manager.is_banned(ip("203.0.113.9")));
        assert_eq!(
            feed.counters()
                .snapshot(ip("203.0.113.9"))
                .values()
                .sum::<u64>(),
            1
        );

        // Handshake 2: the ban arm rejects the same address.
        let response = client
            .get("/probe")
            .remote(peer([203, 0, 113, 9]))
            .dispatch()
            .await;
        assert_eq!(body_of(response).await, "1008 IP banned");
    }

    #[tokio::test]
    async fn whitelisted_client_skips_countries_and_the_rate_limit() {
        let client_ip = ip("198.51.100.7");
        let whitelist =
            IpGateConfig::new([client_ip.to_string()], [] as [&str; 0], [] as [&str; 0])
                .expect("valid lists");
        let limiter = RateLimiter::new(RateLimitConfig {
            enable_rate_limiting: true,
            rate_limit: 1,
            rate_limit_window: 10,
            ..RateLimitConfig::default()
        })
        .expect("valid config");
        let client = probe_client(make_guard_websocket(
            WebSocketGuardConfig::new(detect_config())
                .with_ip_gate(whitelist)
                .with_country_rules(
                    parse_country_lists(["US"], [] as [&str; 0]),
                    Arc::new(FixedCountry("DE")),
                )
                .with_rate_limiting(limiter),
        ))
        .await;
        for _ in 0..3 {
            let response = client
                .get("/probe")
                .remote(peer([198, 51, 100, 7]))
                .dispatch()
                .await;
            assert_eq!(body_of(response).await, "granted");
        }
    }

    #[test]
    fn gate_verdict_whitelist_sets_the_skip_state() {
        // The whitelist skip rides the engine's gate decision shape; pin it
        // so the rate-limit arm's skip contract stays pinned to the engine.
        let whitelist = IpGateConfig::new(
            ["198.51.100.0/24"] as [&str; 1],
            [] as [&str; 0],
            [] as [&str; 0],
        )
        .expect("valid lists");
        let client = ip("198.51.100.7");
        assert!(matches!(
            whitelist.evaluate(client),
            IpGateVerdict::Allowed(IpGateDecision {
                is_whitelisted: true,
                ..
            })
        ));
    }
}
