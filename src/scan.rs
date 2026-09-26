//! The engine call surface shared by the fairing and the guards.
//!
//! Everything in this module is adapter glue: one [`GuardEngine::detect`] call
//! per request view, plus the request-local slots the fairing and the guards
//! use to hand verdicts to each other (and to the catchers).

use crate::BanState;
use guard_core_engine::body_scan::extract_body_scan_values;
use guard_core_engine::detect::{DetectConfig, Threat};
use guard_core_engine::ip_gate::IpGateDecision;
use rocket::Request;
use rocket::http::Status;
use rocket::http::uncased::UncasedStr;
use std::net::IpAddr;
use std::sync::Arc;

use guard_core_engine::ip_ban::RATE_LIMIT_CATEGORY;

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
    /// The engine panicked; fail secure.
    Failed,
}

impl Verdict {
    /// The refusal status this verdict maps to.
    pub(crate) const fn status(self) -> Status {
        match self {
            Verdict::Clean => Status::Ok,
            Verdict::Threat => Status::BadRequest,
            Verdict::IpBlocked | Verdict::Banned | Verdict::ActivityBanned => Status::Forbidden,
            Verdict::RateLimited(_) => Status::TooManyRequests,
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
    /// Detector indirection so unit tests can substitute a panicking
    /// detector and exercise the fail-secure path; production builds always
    /// store [`guard_core_engine::detect::detect`].
    #[cfg(test)]
    pub(crate) detect_fn: crate::DetectFn,
    /// The engine's sliding-window rate limiter, when
    /// [`GuardFairing::with_rate_limiting`](crate::GuardFairing::with_rate_limiting)
    /// installed one.
    pub(crate) rate_limiter: Option<Arc<guard_core_engine::rate_limit::RateLimiter>>,
    /// The dynamic ban store and auto-ban engine, when
    /// [`GuardFairing::with_ip_banning`](crate::GuardFairing::with_ip_banning)
    /// installed one.
    pub(crate) ban_state: Option<Arc<BanState>>,
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
            #[cfg(test)]
            detect_fn: guard_core_engine::detect::detect,
            rate_limiter: None,
            ban_state: None,
        }
    }

    /// One engine call: the flagged view's threat categories, or `None` when
    /// the engine clears the content. Regex threats carry the pattern
    /// table's category; semantic threats carry their attack type.
    fn categories_for(&self, content: &str, view: &str) -> Option<Vec<String>> {
        #[cfg(test)]
        let verdict = (self.detect_fn)(content, view, &self.config);
        #[cfg(not(test))]
        let verdict = guard_core_engine::detect::detect(content, view, &self.config);
        if !verdict.is_threat {
            return None;
        }
        Some(
            verdict
                .threats
                .iter()
                .map(|threat| match threat {
                    Threat::Regex(regex) => regex.category.clone(),
                    Threat::Semantic(semantic) => semantic.attack_type.clone(),
                })
                .collect(),
        )
    }

    /// Scan every metadata view, in the documented order: path, query,
    /// headers. The first view the engine flags wins, and its categories are
    /// the violation categories the auto-ban engine counts.
    pub(crate) fn scan_metadata(&self, request: &Request<'_>) -> Option<Vec<String>> {
        let path = request.uri().path().as_str();
        if path != "/"
            && let Some(categories) = self.categories_for(path, "url_path")
        {
            return Some(categories);
        }

        if let Some(query) = request.uri().query() {
            let query = query.as_str();
            if !query.is_empty()
                && let Some(categories) = self.categories_for(query, "query_param")
            {
                return Some(categories);
            }
        }

        for header in request.headers().iter() {
            if is_excluded_header(header.name()) {
                continue;
            }
            if let Some(categories) = self.categories_for(header.value(), "header") {
                return Some(categories);
            }
        }

        None
    }

    /// Scan the `request_body` view through the engine's body-value
    /// extraction: the body is routed by content type (urlencoded fields,
    /// multipart parts, JSON walks, blob fallback) and every extracted value
    /// is scanned with the context the reference engine scans it under; the
    /// first threat wins. A value with a forced category (a JSON mongo
    /// operator key the reference reports straight from the JSON walk) is a
    /// threat outright. An empty (or whitespace-only) body is not scanned,
    /// mirroring the sibling adapters.
    pub(crate) fn scan_body(&self, request: &Request<'_>, bytes: &[u8]) -> Option<Vec<String>> {
        let text = String::from_utf8_lossy(bytes);
        if text.trim().is_empty() {
            return None;
        }
        let content_type = request
            .headers()
            .get_one("content-type")
            .unwrap_or_default();
        for value in extract_body_scan_values(&text, content_type, &self.config) {
            if let Some(forced) = value.forced_category {
                return Some(vec![forced.to_owned()]);
            }
            if let Some(categories) = self.categories_for(&value.content, &value.context) {
                return Some(categories);
            }
        }
        None
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

/// The client IP, when the request is attributable and not skipped by the
/// `exempt_ips` contract: the stateful stage's gate.
///
/// Unattributed requests cannot be banned, rate limited, or counted (the
/// stage cannot tell who to hold responsible); whitelisted and exempt IPs
/// skip exactly what the reference skips for a whitelist match. Detection
/// applies to both, always.
fn attributed_and_counting(request: &Request<'_>) -> Option<IpAddr> {
    let ip = request.client_ip()?;
    let decision = gate_decision(request).unwrap_or_default();
    if decision.is_whitelisted || decision.is_exempt {
        return None;
    }
    Some(ip)
}

/// The stateful stage: dynamic bans, then rate limiting, in the reference
/// pipeline's order (an IP ban check precedes the rate limiter).
///
/// Returns the verdict when the stage denies the request: [`Verdict::Banned`]
/// for a live ban, [`Verdict::RateLimited`] with the `Retry-After` window for
/// a crossing. Rate-limit autoban: every active crossing counts one
/// `rate_limit` violation toward the auto-ban engine (the reference's
/// `_record_rate_limit_autoban`); the response stays 429 and the ban bites on
/// the next request, which the ban stage answers with 403.
pub(crate) fn state_stage(engine: &GuardEngine, request: &Request<'_>) -> Option<Verdict> {
    let ip = attributed_and_counting(request)?;

    // Ban check first: a banned IP is denied before its rate window is
    // touched, so banned traffic neither consumes budget nor counts
    // violations (the request never reaches the limiter).
    if let Some(ban) = &engine.ban_state
        && ban.config.enable_ip_banning
        && ban.manager.is_banned(ip)
    {
        return Some(Verdict::Banned);
    }

    let limiter = engine.rate_limiter.as_ref()?;
    let decision = limiter.check(ip, None);
    if decision.allowed {
        return None;
    }
    if limiter.config().enable_rate_limit_auto_ban
        && let Some(ban) = &engine.ban_state
    {
        ban.register_violations(ip, &[RATE_LIMIT_CATEGORY], "rate_limit_exceeded");
    }
    Some(Verdict::RateLimited(decision.retry_after()))
}

/// The detection block for one flagged request, with the auto-ban engine
/// attached: the flagged view's categories count as violations for the
/// client IP, and a crossed threshold bans on the spot (the reference
/// pipeline's suspicious-activity stage). Returns [`Verdict::ActivityBanned`]
/// when the ban fired on this request, [`Verdict::Threat`] otherwise.
pub(crate) fn detect_block(
    engine: &GuardEngine,
    request: &Request<'_>,
    categories: &[String],
) -> Verdict {
    // Counting is attribute-gated only: the engine's resolution refuses to
    // ban while the config's enable_ip_banning is off, and the violations
    // still count (enabling banning later starts from observed history).
    if let (Some(ban), Some(ip)) = (engine.ban_state.as_ref(), attributed_and_counting(request)) {
        let category_refs: Vec<&str> = categories.iter().map(String::as_str).collect();
        if ban
            .register_violations(ip, &category_refs, "penetration_attempt")
            .is_some()
        {
            return Verdict::ActivityBanned;
        }
    }
    Verdict::Threat
}

/// Deduplicate and sort the flagged view's categories: the deterministic
/// order the auto-ban engine resolves thresholds in (the Go port sorts too).
pub(crate) fn sort_categories(mut categories: Vec<String>) -> Vec<String> {
    categories.sort_unstable();
    categories.dedup();
    categories
}
