//! The `on_request` / `on_ignite` / `on_response` fairing.

use crate::response;
use crate::scan::{
    GuardEngine, Metadata, Verdict, detect_block, record_gate_decision, sort_categories,
    state_stage,
};
use guard_core_engine::ip_ban::{IpBanConfig, IpBanManager, ViolationCounters};
use guard_core_engine::ip_gate::IpGateVerdict;
use guard_core_engine::rate_limit::RateLimiter;
use rocket::Data;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::Status;
use rocket::request::Request;
use rocket::response::Response;
use rocket::{Build, Rocket};
use std::panic::{AssertUnwindSafe, catch_unwind};

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
    /// counts its categories per client IP (exempt and whitelisted IPs never
    /// count - the `exempt_ips` contract), and a crossed `threat_ban_config`
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

    /// Substitute the detector. Test-only: exercises the fail-secure path.
    #[cfg(test)]
    pub(crate) fn with_detect_fn(mut self, detect_fn: crate::DetectFn) -> Self {
        self.engine.detect_fn = detect_fn;
        self
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
            rocket = rocket.manage(self.engine.clone());
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
        let verdict = request.local_cache(|| Metadata(None)).0;
        if response.status() == Status::NotFound
            && let Some(verdict) = verdict
            && !matches!(verdict, Verdict::Clean | Verdict::Failed)
        {
            *response = response::verdict_response(verdict);
        }
    }
}

impl GuardFairing {
    /// The request's verdict: the IP gate first (a denied client IP is the
    /// verdict, no scan needed), then the stateful stage (dynamic bans, then
    /// rate limiting), then the metadata views, each recovered from an engine
    /// panic as fail-secure.
    fn evaluate(&self, request: &Request<'_>) -> Verdict {
        if let Some(gate) = &self.ip_gate
            && let Some(ip) = request.client_ip()
        {
            match gate.evaluate(ip) {
                IpGateVerdict::Denied(_) => return Verdict::IpBlocked,
                IpGateVerdict::Allowed(decision) => record_gate_decision(request, decision),
            }
        }

        // The stateful stage runs on every attributed, non-exempt request
        // before the scan: a banned or throttled client never reaches
        // detection (banned traffic never consumes rate budget, and the ban
        // check precedes the limiter).
        if let Some(verdict) = state_stage(&self.engine, request) {
            return verdict;
        }

        match catch_unwind(AssertUnwindSafe(|| {
            self.engine
                .scan_metadata(request)
                .map_or(Verdict::Clean, |categories| {
                    detect_block(
                        &self.engine,
                        request,
                        sort_categories(categories).as_slice(),
                    )
                })
        })) {
            Ok(verdict) => verdict,
            Err(_) => Verdict::Failed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BlockGuard, FAILURE_MESSAGE, IpGateConfig};
    use guard_core_engine::detect::{DetectConfig, DetectVerdict};
    use rocket::get;
    use rocket::local::asynchronous::Client;
    use rocket::routes;

    fn panicking_detect(_content: &str, _view: &str, _config: &DetectConfig) -> DetectVerdict {
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
        let fairing = GuardFairing::with_defaults().with_detect_fn(panicking_detect);
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
    use guard_core_engine::ip_ban::{Clock, IpBanConfig, IpBanManager};
    use rocket::get;
    use rocket::http::Status;
    use rocket::local::asynchronous::{Client, LocalResponse};
    use rocket::routes;
    use std::net::IpAddr;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[get("/hello")]
    fn hello_stateful(_guard: BlockGuard) -> &'static str {
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
        RateLimiter::new(RateLimitConfig {
            enable_rate_limiting: true,
            rate_limit: limit,
            rate_limit_window: 60,
            enable_rate_limit_auto_ban: auto_ban,
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
                .mount("/", routes![hello_stateful]),
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
                .mount("/", routes![hello_stateful]),
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
        assert_eq!(body, BANNED_MESSAGE);
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
    async fn exempt_ip_never_counts_detection_violations() {
        // Checklist: the exempt flag makes violation counting observable -
        // an exempt attacker can never be auto-banned.
        let gate = IpGateConfig::new(NIL, NIL, ["198.51.100.7"]).expect("valid lists");
        let config = IpBanConfig::new(
            true,
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
        let fairing = GuardFairing::with_defaults()
            .with_ip_gate(gate)
            .with_ip_banning(IpBanManager::new(), config);
        for _ in 0..3 {
            let (status, body, _) = attack_status(fairing.clone(), "198.51.100.7").await;
            assert_eq!(status, Status::BadRequest);
            assert_eq!(
                body,
                crate::BLOCKED_MESSAGE,
                "exempt violations are not counted, so no ban can fire"
            );
        }
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
}
