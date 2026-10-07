//! The engine call surface shared by the fairing and the guards.
//!
//! Everything in this module is adapter glue: one [`GuardEngine::detect`] call
//! per request view, plus the request-local slots the fairing and the guards
//! use to hand verdicts to each other (and to the catchers).

use crate::BanState;
use guard_core_engine::detect::DetectConfig;
use guard_core_engine::detection_exclusions::{
    DetectionExclusionConfig, RequestScanVerdict, RequestSurfaces, ResolvedExclusions,
    RouteDetectionExclusions, resolve as resolve_exclusions,
};
use guard_core_engine::ip_gate::IpGateDecision;
use guard_core_rs::responses::OnBlockHook;
use guard_core_rs::tower::{
    ObservabilityConfig, RateLimitStage, RequestObservation, StageResponse,
};
use rocket::Request;
use rocket::http::Status;
use rocket::http::uncased::UncasedStr;
use std::sync::Arc;

/// Header names that are never scanned, mirroring the TypeScript adapters'
/// `EXCLUDED_HEADERS` (plus every `sec-*` header).
///
/// Negotiation and routing headers carry attacker-influenced-but-expected
/// values (`Accept`, `User-Agent`, ...) whose scanning costs false positives
/// without buying coverage: a payload smuggled into them must still survive
/// the path, query, and body views.
pub(crate) const EXCLUDED_HEADERS: &[&str] = &[
    "host",
    "user-agent",
    "accept",
    "accept-encoding",
    "connection",
    "origin",
    "referer",
];

/// The outcome of one security evaluation, as stashed in request-local state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Nothing tripped the engine.
    Clean,
    /// At least one view was flagged as a threat.
    Threat,
    /// The IP gate denied the client IP (blacklisted, or a non-empty
    /// whitelist matched neither the IP nor an exemption).
    IpBlocked,
    /// The ban stage found a live ban on the client IP.
    Banned,
    /// A detected threat crossed an auto-ban threshold and the ban fired on
    /// this very request.
    ActivityBanned,
    /// The rate limiter recorded a crossing; the payload is the
    /// `Retry-After` seconds (the window).
    RateLimited(u64),
    /// The distributed backend failed with `redis_fail_open = false`; the
    /// reference's fail-closed `503` shape.
    RedisUnavailable,
    /// Check 2: the emergency-mode gate blocked (the `503` shape; the
    /// resolved body rides the block-body slot).
    EmergencyBlocked,
    /// Checks 6 + 7: a required header failed (the dynamic `400` shape;
    /// the resolved body rides the block-body slot).
    HeadersBlocked,
    /// Check 7: authentication failed (the fixed `401` shape).
    AuthRequired,
    /// Checks 8 / 9 / 10 / 12b / 13 / 14: a stage answered its family
    /// `403` (the resolved body rides the block-body slot).
    StageForbidden,
    /// Check 17 (and a route validator's own response): the block status
    /// the custom function carried.
    CustomBlock(u16),
    /// Check 3: the HTTPS-enforcement stage redirected (the `301` target
    /// rides the redirect-target slot).
    HttpsRedirect,
    /// The engine panicked; fail secure.
    Failed,
}

impl Verdict {
    /// The refusal status this verdict maps to.
    pub(crate) const fn status(self) -> Status {
        match self {
            Verdict::Clean => Status::Ok,
            Verdict::Threat | Verdict::HeadersBlocked => Status::BadRequest,
            Verdict::IpBlocked
            | Verdict::Banned
            | Verdict::ActivityBanned
            | Verdict::StageForbidden => Status::Forbidden,
            Verdict::RateLimited(_) => Status::TooManyRequests,
            Verdict::RedisUnavailable | Verdict::EmergencyBlocked => Status::ServiceUnavailable,
            Verdict::AuthRequired => Status::Unauthorized,
            Verdict::CustomBlock(status) => match Status::from_code(status) {
                Some(status) => status,
                None => Status::InternalServerError,
            },
            Verdict::HttpsRedirect => Status::MovedPermanently,
            Verdict::Failed => Status::InternalServerError,
        }
    }
}

/// Request-local slot written by [`crate::GuardFairing`] during `on_request`.
///
/// A distinct type from [`Enforced`] on purpose: Rocket's request-local cache
/// keeps the _first_ value written for a type, so the fairing's metadata
/// verdict and a guard's later enforcement verdict need separate slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Metadata(pub(crate) Option<Verdict>);

/// Request-local slot written by a guard when it refuses a request.
///
/// This is what lets the registered catchers tell a guard refusal (which gets
/// the ecosystem plain-text body) apart from an application error with
/// the same status (which keeps a minimal default body).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Enforced(pub(crate) Option<Verdict>);

/// The engine entry point, stored once per application in managed state.
///
/// [`crate::GuardFairing::on_ignite`] manages it (unless the application
/// already managed one), so the fairing and every guard read the same
/// configuration and the same detector.
#[derive(Clone)]
pub(crate) struct GuardEngine {
    /// Detection knobs passed to every engine call.
    pub(crate) config: DetectConfig,
    /// Body buffering cap in bytes, enforced by [`crate::GuardBody`].
    pub(crate) body_cap: usize,
    /// Scan indirection so unit tests can substitute a panicking scanner
    /// and exercise the fail-secure path; production builds always store
    /// [`guard_core_engine::detection_exclusions::scan_request`].
    pub(crate) scan_fn: crate::ScanFn,
    /// The engine's sliding-window rate limiter, when
    /// [`GuardFairing::with_rate_limiting`](crate::GuardFairing::with_rate_limiting)
    /// installed one.
    pub(crate) rate_limiter: Option<Arc<guard_core_engine::rate_limit::RateLimiter>>,
    /// The dynamic ban store and auto-ban engine, when
    /// [`GuardFairing::with_ip_banning`](crate::GuardFairing::with_ip_banning)
    /// installed one.
    pub(crate) ban_state: Option<Arc<BanState>>,
    /// The global detection-exclusion config, when
    /// [`GuardFairing::with_detection_exclusions`](crate::GuardFairing::with_detection_exclusions)
    /// installed one.
    pub(crate) detection_exclusions: Option<DetectionExclusionConfig>,
    /// The per-route detection-exclusion resolver
    /// (`path -> Option<RouteDetectionExclusions>`).
    pub(crate) route_exclusions: Option<RouteExclusionsResolver>,
    /// The engine facade's rate-limit stage: every stateful decision and
    /// emission goes through it. Built by the fairing in `on_ignite`.
    pub(crate) stage: Option<Arc<RateLimitStage>>,
    /// The observability knobs (for the adapter-rendered `400` block).
    pub(crate) observability: Option<ObservabilityConfig>,
    /// The reference `on_block` hook (for the adapter-rendered `400`).
    pub(crate) on_block: Option<OnBlockHook>,
    /// The status-to-body overrides (for the adapter-rendered `400`).
    pub(crate) custom_error_responses: crate::CustomErrorResponses,
}

impl GuardEngine {
    /// Build an engine from a detection configuration.
    ///
    /// The body cap starts at `config.max_full_scan_bytes`, the engine's own
    /// full-scan cap, so a body the engine would fully scan is never rejected
    /// by the adapter for being too large.
    pub(crate) fn new(config: DetectConfig) -> Self {
        Self {
            body_cap: config.max_full_scan_bytes,
            config,
            scan_fn: guard_core_engine::detection_exclusions::scan_request,
            rate_limiter: None,
            ban_state: None,
            detection_exclusions: None,
            route_exclusions: None,
            stage: None,
            observability: None,
            on_block: None,
            custom_error_responses: crate::CustomErrorResponses::new(),
        }
    }

    /// Resolve the per-request detection-exclusion surface: the global
    /// config (the route-exclusion resolver supplies the per-route half)
    /// merging through the engine's `resolve`.
    fn resolved_exclusions(&self, request: &Request<'_>) -> ResolvedExclusions {
        let route: Option<RouteDetectionExclusions> =
            route_detection_exclusions(request).or_else(|| {
                self.route_exclusions
                    .as_ref()
                    .and_then(|resolver| resolver(request.uri().path().as_str()))
            });
        resolve_exclusions(self.detection_exclusions.as_ref(), route.as_ref())
    }

    /// The reference multi-surface scan (`detection_exclusions::scan_request`)
    /// over the metadata views: URL path, `parse_qsl`-decoded query
    /// parameter pairs (per pair, so excluded names are skippable), and the
    /// headers the adapter's framework-noise pre-filter leaves through. The
    /// engine applies the reference exclusion semantics exactly: excluded
    /// headers scan with their false-positive categories suppressed
    /// (`ssrf` for address-chain values), the enabled-categories set filters
    /// per value, and `detection_scan_body = false` affects the body
    /// surface only.
    fn scan_surfaces(&self, request: &Request<'_>, raw_body: Option<&[u8]>) -> RequestScanVerdict {
        let resolved = self.resolved_exclusions(request);

        let path = request.uri().path().as_str();
        let url_path = if path == "/" { None } else { Some(path) };

        let query_params: Vec<(String, String)> = request
            .uri()
            .query()
            .map_or("", |query| query.as_str())
            .split('&')
            .filter(|pair| !pair.is_empty())
            .map(|pair| match pair.split_once('=') {
                Some((name, value)) => {
                    (decode_query_component(name), decode_query_component(value))
                }
                None => (decode_query_component(pair), String::new()),
            })
            .collect();

        let headers: Vec<(String, String)> = request
            .headers()
            .iter()
            .filter(|header| !is_excluded_header(header.name()))
            .map(|header| (header.name().as_str().to_owned(), header.value().to_owned()))
            .collect();

        let content_type = request
            .headers()
            .get_one("content-type")
            .unwrap_or_default();
        let raw_body = raw_body
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
            .unwrap_or_default();

        let surfaces = RequestSurfaces {
            url_path,
            query_params: &query_params,
            headers: &headers,
            content_type,
            raw_body: &raw_body,
        };
        (self.scan_entry())(&surfaces, &resolved, &self.config)
    }

    /// The scan entry point stored on the engine (test-only panic
    /// injection); production builds always store the engine's
    /// `detection_exclusions::scan_request`.
    pub(crate) const fn scan_entry(
        &self,
    ) -> fn(&RequestSurfaces<'_>, &ResolvedExclusions, &DetectConfig) -> RequestScanVerdict {
        self.scan_fn
    }

    /// Scan the metadata views (path, query, headers): the first flagged
    /// view's verdict feeds the auto-ban engine, whose categories the
    /// stage counts.
    pub(crate) fn scan_metadata(&self, request: &Request<'_>) -> Option<RequestScanVerdict> {
        let verdict = self.scan_surfaces(request, None);
        verdict.is_threat.then_some(verdict)
    }

    /// Scan the `request_body` view through the engine's body-value
    /// extraction: the body is routed by content type (urlencoded fields,
    /// multipart parts, JSON walks, blob fallback) and every extracted
    /// value is scanned under the context the reference engine scans it
    /// under; excluded body fields skip, and `detection_scan_body = false`
    /// skips the surface entirely.
    pub(crate) fn scan_body(
        &self,
        request: &Request<'_>,
        bytes: &[u8],
    ) -> Option<RequestScanVerdict> {
        let text = String::from_utf8_lossy(bytes);
        if text.trim().is_empty() {
            return None;
        }
        let verdict = self.scan_surfaces(request, Some(bytes));
        verdict.is_threat.then_some(verdict)
    }
}

/// Whether a header name is on the exclusion list.
///
/// Matching is case-insensitive, so the decision does not depend on the
/// casing the client sent.
pub(crate) fn is_excluded_header(name: &UncasedStr) -> bool {
    name.starts_with("sec-") || EXCLUDED_HEADERS.iter().any(|excluded| name == *excluded)
}

/// Read the fairing's metadata verdict, if the fairing ran.
pub(crate) fn metadata_verdict(request: &Request<'_>) -> Option<Verdict> {
    request.local_cache(|| Metadata(None)).0
}

/// Read the enforcement verdict written by a guard, if one refused.
pub(crate) fn enforced_verdict(request: &Request<'_>) -> Option<Verdict> {
    request.local_cache(|| Enforced(None)).0
}

/// Record why a guard is refusing this request, so the catcher can produce
/// the ecosystem's plain-text body instead of a generic default.
pub(crate) fn record_enforced(request: &Request<'_>, verdict: Verdict) {
    request.local_cache(|| Enforced(Some(verdict)));
}

/// Request-local slot for the global IP gate's skip state: what a passed
/// request's gate evaluation decided (`is_whitelisted` / `is_exempt`). The
/// stateful stages read it; a distinct type from [`Metadata`] because the
/// request-local cache keeps only the first value per type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GateDecision(pub(crate) Option<IpGateDecision>);

/// The gate's skip state for this request, if the gate ran and passed.
pub(crate) fn gate_decision(request: &Request<'_>) -> Option<IpGateDecision> {
    request.local_cache(|| GateDecision(None)).0
}

/// Record the gate's skip state for a passed request.
pub(crate) fn record_gate_decision(request: &Request<'_>, decision: IpGateDecision) {
    request.local_cache(|| GateDecision(Some(decision)));
}

/// The request pieces the stage's event and log emissions read.
pub(crate) fn request_observation(request: &Request<'_>) -> RequestObservation {
    let mut url = request.uri().path().as_str().to_owned();
    if let Some(query) = request.uri().query() {
        url.push('?');
        url.push_str(query.as_str());
    }
    RequestObservation {
        method: Some(request.method().as_str().to_owned()),
        url: Some(url),
        user_agent: request.headers().get_one("user-agent").map(str::to_owned),
    }
}

/// The reference block shapes mapped onto the request-local verdicts; the
/// `custom_error_responses` body override, when one applied, rides along.
pub(crate) fn verdict_from_stage(response: &StageResponse) -> (Verdict, Option<String>) {
    let custom = response.custom_body.clone();
    match (response.status.as_u16(), response.body) {
        (403, crate::response::BANNED_MESSAGE) => (Verdict::Banned, custom),
        (403, _) => (Verdict::ActivityBanned, custom),
        // The family contract's below-threshold detection answer: the
        // stage serves the reference suspicious-activity `400 "Suspicious
        // activity detected"` body itself (the only `400` shape the stage
        // emits), which is the plain `Threat` block shape this adapter
        // renders for a flagged attack.
        (400, _) => (Verdict::Threat, custom),
        (429, _) => (
            Verdict::RateLimited(response.retry_after.unwrap_or(0)),
            custom,
        ),
        (503, _) => (Verdict::RedisUnavailable, custom),
        _ => (Verdict::Failed, custom),
    }
}

/// The stashed `custom_error_responses` body override, if the stage
/// carried one for this request's refusal.
pub(crate) fn block_body_override(request: &Request<'_>) -> Option<String> {
    request
        .local_cache(|| BlockBody(std::sync::Mutex::new(None)))
        .0
        .lock()
        .expect("block body slot")
        .clone()
}

/// Record the block-body override for the catchers to render.
pub(crate) fn record_block_body(request: &Request<'_>, custom: Option<String>) {
    if let Some(body) = custom {
        *request
            .local_cache(|| BlockBody(std::sync::Mutex::new(None)))
            .0
            .lock()
            .expect("block body slot") = Some(body);
    }
}

/// One engine-stage pass over the request (bans, then the rate-limit
/// tiers, then the metadata finding): the fairing's `on_request` flow.
/// Returns the verdict and the block-body override, or `None` for
/// pass-through (including passive mode, where the finding below was still
/// observed and counted by the stage).
pub(crate) fn stage_decision(
    engine: &GuardEngine,
    request: &Request<'_>,
    finding: Option<&RequestScanVerdict>,
) -> Option<(Verdict, Option<String>)> {
    // The tiers + detection-feed half only: the ban arm ran earlier in the
    // fairing's `on_request` pass, at the reference position (before the
    // geo, cloud-provider, and user-agent checks).
    let stage = engine.stage.as_ref()?;
    let finding = finding.map(|verdict| guard_core_rs::tower::ThreatFinding {
        is_threat: true,
        categories: verdict.categories.clone(),
        trigger_info: verdict.reason.clone(),
    });
    let tiers = route_rate_limits(request);
    let decision = stage.decide_tiers_observed(
        request.client_ip(),
        Some(request.uri().path().as_str()),
        tiers.as_ref(),
        gate_decision(request),
        finding.as_ref(),
        Some(&request_observation(request)),
    );
    let decision = decision?;
    let (verdict, custom) = verdict_from_stage(&decision);
    record_block_body(request, custom);
    Some((verdict, None))
}

/// The ban arm alone (the reference `ip_security` ban check): the fairing's
/// first stage pass, before the geo, cloud-provider, and user-agent checks.
pub(crate) fn bans_decision(engine: &GuardEngine, request: &Request<'_>) -> Option<Verdict> {
    let stage = engine.stage.as_ref()?;
    let decision =
        stage.decide_bans_observed(request.client_ip(), Some(&request_observation(request)))?;
    let (verdict, custom) = verdict_from_stage(&decision);
    record_block_body(request, custom);
    Some(verdict)
}

/// A stage block with its own status and resolved body (the required
/// headers, referrer, validators, time-window, geo, cloud, user-agent, and
/// custom-request checks): the body lands in the block-body slot the
/// catchers and the `404` rewrite render.
pub(crate) fn stage_block(request: &Request<'_>, status: u16, body: &str) -> Verdict {
    record_block_body(request, Some(body.to_owned()));
    match status {
        400 => Verdict::HeadersBlocked,
        401 => Verdict::AuthRequired,
        403 => Verdict::StageForbidden,
        503 => Verdict::EmergencyBlocked,
        other => Verdict::CustomBlock(other),
    }
}

/// The below-threshold detection block for a metadata finding: the plain
/// `Threat` verdict (the `400` shape), suppressed under passive mode.
pub(crate) fn metadata_threat_verdict(
    engine: &GuardEngine,
    request: &Request<'_>,
    verdict: &RequestScanVerdict,
) -> Verdict {
    let passive = engine
        .stage
        .as_ref()
        .is_some_and(|stage| stage.config().passive_mode);
    if passive {
        return Verdict::Clean;
    }
    // The plain `400` block, with the `custom_error_responses` override and
    // the reference `on_block` payload (the stage fired only for its own
    // crossings; this block shape is the adapter's).
    let body = guard_core_rs::responses::resolve_error_body(
        &engine.custom_error_responses,
        400,
        crate::response::BLOCKED_MESSAGE,
    );
    record_block_body(request, Some(body));
    if let Some(observability) = &engine.observability {
        let ip = request
            .client_ip()
            .map(|ip| ip.to_string())
            .unwrap_or_default();
        let observation = request_observation(request);
        let payload = guard_core_rs::responses::build_block_payload(
            "suspicious_activity",
            &format!("Suspicious activity detected: {ip}"),
            &verdict.reason,
            false,
            &ip,
            observation.url.as_deref().unwrap_or("/"),
            observation.method.as_deref().unwrap_or(""),
            Some(400),
            &observability.sensitive,
        );
        guard_core_rs::responses::fire_block_hook(engine.on_block.as_ref(), &payload);
    }
    Verdict::Threat
}

/// The body finding, fed through the stage's split detection feed
/// (`feed_finding`: no ban check, no rate-limit tier re-recording - the
/// `on_request` pass already recorded the window once). A crossed
/// threshold answers `ActivityBanned`, otherwise the plain `Threat` block
/// shape; passive mode renders nothing.
pub(crate) fn enforce_body_finding(
    engine: &GuardEngine,
    request: &Request<'_>,
    verdict: &RequestScanVerdict,
) -> Verdict {
    let Some(stage) = engine.stage.as_ref() else {
        return Verdict::Threat;
    };
    let finding = guard_core_rs::tower::ThreatFinding {
        is_threat: true,
        categories: verdict.categories.clone(),
        trigger_info: verdict.reason.clone(),
    };
    let gate = gate_decision(request);
    let whitelisted = gate.is_some_and(|gate| gate.is_whitelisted);
    let crossed = stage.feed_finding(
        request.client_ip(),
        whitelisted,
        Some(&finding),
        Some(&request_observation(request)),
    );
    if let Some(answer) = crossed {
        let (verdict, custom) = verdict_from_stage(&answer);
        record_block_body(request, custom);
        return verdict;
    }
    if stage.config().passive_mode {
        Verdict::Clean
    } else {
        Verdict::Threat
    }
}

/// Request-local slot for the per-route rate-limit tier override (the
/// Rocket counterpart of the reference's `request.state.route_config`).
/// Interior-mutable because Rocket's request-local cache hands out shared
/// references.
pub(crate) struct RouteTiers(pub(crate) std::sync::Mutex<Option<crate::RouteRateLimits>>);

/// Request-local slot for the block-body override
/// (`custom_error_responses`). Interior-mutable for the same reason.
pub(crate) struct BlockBody(pub(crate) std::sync::Mutex<Option<String>>);

/// Request-local slot for the HTTPS redirect target (check 3's
/// scheme-upgraded URL). Interior-mutable for the same reason.
pub(crate) struct RedirectTarget(pub(crate) std::sync::Mutex<Option<String>>);

/// The redirect target the HTTPS-enforcement stage composed, if any.
pub(crate) fn redirect_target(request: &Request<'_>) -> Option<String> {
    request
        .local_cache(|| RedirectTarget(std::sync::Mutex::new(None)))
        .0
        .lock()
        .expect("redirect target slot")
        .clone()
}

/// Record the HTTPS redirect target for the `on_response` rewrite.
pub(crate) fn record_redirect_target(request: &Request<'_>, target: String) {
    *request
        .local_cache(|| RedirectTarget(std::sync::Mutex::new(None)))
        .0
        .lock()
        .expect("redirect target slot") = Some(target);
}

/// Request-local slot for the per-route detection-exclusion override.
pub(crate) struct RouteExclusions(pub(crate) std::sync::Mutex<Option<RouteDetectionExclusions>>);

/// Read the route tier override, if a preceding fairing or guard set one.
pub(crate) fn route_rate_limits(request: &Request<'_>) -> Option<crate::RouteRateLimits> {
    request
        .local_cache(|| RouteTiers(std::sync::Mutex::new(None)))
        .0
        .lock()
        .expect("route tiers slot")
        .clone()
}

/// Set the per-route rate-limit tier override for this request (a
/// preceding fairing or guard calls it before the request's security pass
/// reads it).
pub fn set_route_rate_limits(request: &Request<'_>, tiers: crate::RouteRateLimits) {
    *request
        .local_cache(|| RouteTiers(std::sync::Mutex::new(None)))
        .0
        .lock()
        .expect("route tiers slot") = Some(tiers);
}

/// Set the per-route detection-exclusion override for this request (a
/// non-`None` route value replaces the global set for that surface; the
/// header set always merges).
pub fn set_route_detection_exclusions(request: &Request<'_>, exclusions: RouteDetectionExclusions) {
    *request
        .local_cache(|| RouteExclusions(std::sync::Mutex::new(None)))
        .0
        .lock()
        .expect("route exclusions slot") = Some(exclusions);
}

pub(crate) fn route_detection_exclusions(
    request: &Request<'_>,
) -> Option<RouteDetectionExclusions> {
    request
        .local_cache(|| RouteExclusions(std::sync::Mutex::new(None)))
        .0
        .lock()
        .expect("route exclusions slot")
        .clone()
}

/// The per-route detection-exclusion resolver:
/// `path -> Option<RouteDetectionExclusions>`.
pub(crate) type RouteExclusionsResolver =
    Arc<dyn Fn(&str) -> Option<RouteDetectionExclusions> + Send + Sync>;

/// `urllib.parse.unquote_plus` for one query component: `%XX` runs and `+`
/// (form-encoding's space) decode into the value the reference's
/// `parse_qsl` hands the engine. Malformed escapes stay literal.
fn decode_query_component(component: &str) -> String {
    let plus_decoded = component.replace('+', " ");
    let bytes = plus_decoded.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let Ok(byte) = u8::from_str_radix(
                std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or(""),
                16,
            )
        {
            out.push(byte);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::response::{
        ACTIVITY_BANNED_MESSAGE, BANNED_MESSAGE, BLOCKED_MESSAGE, FAILURE_MESSAGE,
        RATE_LIMITED_MESSAGE, REDIS_UNAVAILABLE_MESSAGE,
    };
    use guard_core_rs::tower::StageResponse;

    #[test]
    fn verdict_status_mapping_covers_every_shape() {
        assert_eq!(Verdict::Clean.status(), Status::Ok);
        assert_eq!(Verdict::Threat.status(), Status::BadRequest);
        assert_eq!(Verdict::IpBlocked.status(), Status::Forbidden);
        assert_eq!(Verdict::Banned.status(), Status::Forbidden);
        assert_eq!(Verdict::ActivityBanned.status(), Status::Forbidden);
        assert_eq!(Verdict::RateLimited(30).status(), Status::TooManyRequests);
        assert_eq!(
            Verdict::RedisUnavailable.status(),
            Status::ServiceUnavailable
        );
        assert_eq!(Verdict::Failed.status(), Status::InternalServerError);
    }

    #[test]
    fn custom_block_status_mapping_covers_both_from_code_arms() {
        // A stage answering its own status resolves through
        // `Status::from_code`; an unassignable code falls to the `500`.
        assert_eq!(
            Verdict::CustomBlock(418).status(),
            Status::from_code(418).expect("418 assigns")
        );
        assert_eq!(
            Verdict::CustomBlock(60000).status(),
            Status::InternalServerError
        );
    }

    /// A stage answer with the given status and default body, as the stage
    /// emits it (no custom override, no `Retry-After` unless asked).
    fn stage_answer(status: http::StatusCode, body: &'static str) -> StageResponse {
        StageResponse {
            status,
            body,
            retry_after: None,
            custom_body: None,
        }
    }

    #[test]
    fn verdict_from_stage_maps_every_family_answer() {
        assert_eq!(
            verdict_from_stage(&stage_answer(http::StatusCode::FORBIDDEN, BANNED_MESSAGE)),
            (Verdict::Banned, None)
        );
        assert_eq!(
            verdict_from_stage(&stage_answer(
                http::StatusCode::FORBIDDEN,
                ACTIVITY_BANNED_MESSAGE
            )),
            (Verdict::ActivityBanned, None)
        );
        assert_eq!(
            verdict_from_stage(&stage_answer(
                http::StatusCode::BAD_REQUEST,
                BLOCKED_MESSAGE
            )),
            (Verdict::Threat, None)
        );
        let mut throttled = stage_answer(http::StatusCode::TOO_MANY_REQUESTS, RATE_LIMITED_MESSAGE);
        throttled.retry_after = Some(30);
        assert_eq!(
            verdict_from_stage(&throttled),
            (Verdict::RateLimited(30), None)
        );
        assert_eq!(
            verdict_from_stage(&stage_answer(
                http::StatusCode::SERVICE_UNAVAILABLE,
                REDIS_UNAVAILABLE_MESSAGE
            )),
            (Verdict::RedisUnavailable, None)
        );
        // Anything outside the family shapes is treated as an internal
        // failure (fail secure).
        assert_eq!(
            verdict_from_stage(&stage_answer(
                http::StatusCode::IM_A_TEAPOT,
                FAILURE_MESSAGE
            )),
            (Verdict::Failed, None)
        );
    }

    #[test]
    fn verdict_from_stage_carries_the_custom_body_override() {
        let mut answer = stage_answer(http::StatusCode::BAD_REQUEST, BLOCKED_MESSAGE);
        answer.custom_body = Some("blocked:custom".to_owned());
        assert_eq!(
            verdict_from_stage(&answer),
            (Verdict::Threat, Some("blocked:custom".to_owned()))
        );
    }
}
