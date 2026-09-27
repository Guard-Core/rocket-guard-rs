//! Short-circuit responses and the registered catchers that render them.
//!
//! Rocket guards cannot respond directly: an error outcome is dispatched to
//! the error catcher for its status. The adapter therefore registers catchers
//! for the statuses its guards can produce, so every refusal carries the
//! ecosystem's error shape (the bare message, `text/plain; charset=utf-8`,
//! same as the Python family).
//!
//! Scoping: the `403` and `500` catchers only emit the guard body when
//! request-local state shows the refusal came from this adapter's guards
//! ([`Enforced`](crate::scan::Enforced) or a stashed metadata verdict);
//! otherwise they fall back to a minimal default body, because Rocket has no
//! public way to delegate to its own default catcher. The same scoping
//! applies to the `400` and `429` catchers. The `413` catcher is
//! deliberately unscoped: "payload too large" has one meaning regardless of
//! which limit tripped, and Rocket's own `Json` guard maps a limit violation
//! to a `413` error outcome, which then gets the same body.

use crate::scan::{Verdict, enforced_verdict, metadata_verdict};
use rocket::catcher::{BoxFuture, Catcher};
use rocket::http::{ContentType, Status};
use rocket::request::Request;
use rocket::response::Response;
use std::io::Cursor;

/// Detail message carried by the `400 Bad Request` block response.
pub const BLOCKED_MESSAGE: &str = "Suspicious activity detected";

/// Detail message carried by the IP gate's `403 Forbidden` response.
pub const FORBIDDEN_MESSAGE: &str = "Forbidden";

/// Detail message carried by the ban stage's `403 Forbidden` response.
pub const BANNED_MESSAGE: &str = "IP address banned";

/// Detail message carried by the `403 Forbidden` response when a detected
/// threat crossed an auto-ban threshold and the ban fired on this request.
pub const ACTIVITY_BANNED_MESSAGE: &str = "IP has been banned";

/// Detail message carried by the `429 Too Many Requests` response.
pub const RATE_LIMITED_MESSAGE: &str = "Too many requests";

/// Detail message carried by the `413 Payload Too Large` response.
pub const OVERSIZE_MESSAGE: &str = "Payload too large";

/// Detail message carried by the fail-secure `500 Internal Server Error`
/// response.
pub const FAILURE_MESSAGE: &str = "Security check failed";

/// Minimal default bodies for statuses a catcher receives without any
/// adapter state on the request.
///
/// Rocket's own default catcher is `pub(crate)`, so there is no way to
/// delegate to it; these keep the status (and content type) honest without
/// trying to reproduce Rocket's templated pages.
const DEFAULT_400: &str = "400 Bad Request";
const DEFAULT_403: &str = "403 Forbidden";
const DEFAULT_429: &str = "429 Too Many Requests";
const DEFAULT_500: &str = "500 Internal Server Error";
const DEFAULT_503: &str = "503 Service Unavailable";
pub(crate) const REDIS_UNAVAILABLE_MESSAGE: &str = "Redis rate limiting unavailable";

/// The catchers this adapter registers, scoped to the base they are passed
/// to.
///
/// [`crate::GuardFairing`] registers these automatically during `on_ignite`,
/// skipping any status the application already registered a catcher for
/// (Rocket treats same-code catchers at the same base as a fatal collision).
/// Register them manually instead when the application attaches no fairing
/// but uses [`crate::BlockGuard`] or [`crate::GuardBody`]:
///
/// ```ignore
/// rocket::build().register("/", rocket_guard_rs::guard_catchers())
/// ```
#[must_use]
pub fn guard_catchers() -> Vec<Catcher> {
    vec![
        Catcher::new(400, blocked),
        Catcher::new(403, forbidden),
        Catcher::new(413, oversize),
        Catcher::new(429, rate_limited),
        Catcher::new(500, failure),
        Catcher::new(503, service_unavailable),
    ]
}

/// The verdict a `400`/`403`/`429` catcher is rendering, if the refusal came
/// from this adapter: the stashed metadata verdict, else a guard's enforced
/// verdict.
fn refusal_verdict(request: &Request<'_>) -> Option<Verdict> {
    metadata_verdict(request)
        .filter(|verdict| *verdict != Verdict::Clean)
        .or_else(|| enforced_verdict(request).filter(|verdict| *verdict != Verdict::Clean))
}

/// `400` catcher: the block body when a guard detected a threat, a minimal
/// default otherwise.
fn blocked<'r>(status: Status, request: &'r Request<'_>) -> BoxFuture<'r> {
    let custom = custom_body(request);
    if let Some(body) = custom {
        return finish_owned(status, body, None);
    }
    let message = if refusal_verdict(request) == Some(Verdict::Threat) {
        BLOCKED_MESSAGE
    } else {
        DEFAULT_400
    };
    finish(status, message, None)
}

/// `403` catcher: the gate/ban body when a guard blocked this request, a
/// minimal default otherwise.
fn forbidden<'r>(status: Status, request: &'r Request<'_>) -> BoxFuture<'r> {
    if let Some(body) = custom_body(request) {
        return finish_owned(status, body, None);
    }
    let message = match refusal_verdict(request) {
        Some(Verdict::IpBlocked) => FORBIDDEN_MESSAGE,
        Some(Verdict::Banned) => BANNED_MESSAGE,
        Some(Verdict::ActivityBanned) => ACTIVITY_BANNED_MESSAGE,
        _ => DEFAULT_403,
    };
    finish(status, message, None)
}

/// `413` catcher: always the oversize body.
///
/// Unscoped on purpose: a `413` error outcome has one meaning whichever
/// guard or framework limit produced it (Rocket's own `Json` guard maps
/// limit violations to `413`).
fn oversize<'r>(status: Status, _request: &'r Request<'_>) -> BoxFuture<'r> {
    finish(status, OVERSIZE_MESSAGE, None)
}

/// `429` catcher: the throttled body with its `Retry-After` header when the
/// rate limiter blocked this request, a minimal default otherwise.
fn rate_limited<'r>(status: Status, request: &'r Request<'_>) -> BoxFuture<'r> {
    match refusal_verdict(request) {
        Some(Verdict::RateLimited(retry_after)) => match custom_body(request) {
            Some(body) => finish_owned(status, body, Some(retry_after)),
            None => finish(status, RATE_LIMITED_MESSAGE, Some(retry_after)),
        },
        _ => finish(status, DEFAULT_429, None),
    }
}

/// `503` catcher: the fail-closed Redis-unavailable body when the
/// distributed backend refused the request, a minimal default otherwise.
fn service_unavailable<'r>(status: Status, request: &'r Request<'_>) -> BoxFuture<'r> {
    let guard_caused = metadata_verdict(request) == Some(Verdict::RedisUnavailable)
        || enforced_verdict(request) == Some(Verdict::RedisUnavailable);
    finish(
        status,
        if guard_caused {
            REDIS_UNAVAILABLE_MESSAGE
        } else {
            DEFAULT_503
        },
        None,
    )
}

/// `500` catcher: the fail-secure body when a guard failed this request, a
/// minimal default otherwise.
fn failure<'r>(status: Status, request: &'r Request<'_>) -> BoxFuture<'r> {
    let guard_caused = metadata_verdict(request) == Some(Verdict::Failed)
        || enforced_verdict(request) == Some(Verdict::Failed);
    finish(
        status,
        if guard_caused {
            FAILURE_MESSAGE
        } else {
            DEFAULT_500
        },
        None,
    )
}

/// The stashed `custom_error_responses` body override for this request,
/// when the guard's refusal carries one.
fn custom_body(request: &Request<'_>) -> Option<String> {
    crate::scan::block_body_override(request)
}

/// The catcher response for a composed body.
fn finish_owned<'r>(status: Status, message: String, retry_after: Option<u64>) -> BoxFuture<'r> {
    Box::pin(async move {
        let mut build = Response::build();
        build.status(status).header(ContentType::Plain);
        if let Some(after) = retry_after {
            build.raw_header("Retry-After", after.to_string());
        }
        build.sized_body(message.len(), Cursor::new(message)).ok()
    })
}

/// The catcher response: the bare message, `text/plain; charset=utf-8`, and
/// an optional `Retry-After` header for the throttled shape.
fn finish<'r>(status: Status, message: &'static str, retry_after: Option<u64>) -> BoxFuture<'r> {
    Box::pin(async move {
        let mut build = Response::build();
        build.status(status).header(ContentType::Plain);
        if let Some(after) = retry_after {
            build.raw_header("Retry-After", after.to_string());
        }
        build
            .sized_body(message.len(), Cursor::new(message.as_bytes().to_vec()))
            .ok()
    })
}

/// The standalone response for an unrouted request the fairing blocked: the
/// `404` rewrite in [`crate::GuardFairing`] replaces Rocket's not-found page
/// with the verdict's family shape, so probe traffic never reveals route
/// inventory.
pub(crate) fn verdict_response(request: &Request<'_>, verdict: Verdict) -> Response<'static> {
    // The `custom_error_responses` override, when the stage carried one,
    // wins over the family default (same precedence as the catchers).
    if let Some(body) = crate::scan::block_body_override(request) {
        let status = verdict.status();
        return Response::build()
            .status(status)
            .header(ContentType::Plain)
            .sized_body(body.len(), Cursor::new(body.into_bytes()))
            .finalize();
    }
    verdict_response_plain(verdict)
}

pub(crate) fn verdict_response_plain(verdict: Verdict) -> Response<'static> {
    match verdict {
        Verdict::Threat => plain_response(Status::BadRequest, BLOCKED_MESSAGE),
        Verdict::IpBlocked => plain_response(Status::Forbidden, FORBIDDEN_MESSAGE),
        Verdict::Banned => plain_response(Status::Forbidden, BANNED_MESSAGE),
        Verdict::ActivityBanned => plain_response(Status::Forbidden, ACTIVITY_BANNED_MESSAGE),
        Verdict::RateLimited(retry_after) => {
            let mut response = plain_response(Status::TooManyRequests, RATE_LIMITED_MESSAGE);
            response.set_raw_header("Retry-After", retry_after.to_string());
            response
        }
        Verdict::RedisUnavailable => plain_response(
            Status::ServiceUnavailable,
            "Redis rate limiting unavailable",
        ),
        Verdict::Clean | Verdict::Failed => {
            plain_response(Status::InternalServerError, FAILURE_MESSAGE)
        }
    }
}

/// The ecosystem's error shape: the bare message, `text/plain; charset=utf-8`.
fn plain_response(status: Status, message: &'static str) -> Response<'static> {
    Response::build()
        .status(status)
        .header(ContentType::Plain)
        .sized_body(message.len(), Cursor::new(message.as_bytes().to_vec()))
        .finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_response_covers_every_block_shape() {
        let response = verdict_response_plain(Verdict::Threat);
        assert_eq!(response.status(), Status::BadRequest);
        let response = verdict_response_plain(Verdict::IpBlocked);
        assert_eq!(response.status(), Status::Forbidden);
        let response = verdict_response_plain(Verdict::Banned);
        assert_eq!(response.status(), Status::Forbidden);
        let response = verdict_response_plain(Verdict::ActivityBanned);
        assert_eq!(response.status(), Status::Forbidden);
        let response = verdict_response_plain(Verdict::RateLimited(60));
        assert_eq!(response.status(), Status::TooManyRequests);
        assert_eq!(response.headers().get_one("Retry-After"), Some("60"));
        let response = verdict_response_plain(Verdict::RedisUnavailable);
        assert_eq!(response.status(), Status::ServiceUnavailable);
    }
}
