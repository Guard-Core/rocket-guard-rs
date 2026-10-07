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

/// Detail message carried by the required-headers/authentication stage's
/// `401` response (the reference `AuthenticationCheck` default).
pub const AUTHENTICATION_REQUIRED_MESSAGE: &str = "Authentication required";

/// Detail message carried by the emergency-mode stage's `503` response.
pub const EMERGENCY_MESSAGE: &str = "Service temporarily unavailable";

/// Minimal default bodies for statuses a catcher receives without any
/// adapter state on the request.
///
/// Rocket's own default catcher is `pub(crate)`, so there is no way to
/// delegate to it; these keep the status (and content type) honest without
/// trying to reproduce Rocket's templated pages.
const DEFAULT_400: &str = "400 Bad Request";
const DEFAULT_401: &str = "401 Unauthorized";
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
        Catcher::new(401, unauthorized),
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

/// `401` catcher: the authentication-required body when the headers/auth
/// stage refused this request, a minimal default otherwise.
fn unauthorized<'r>(status: Status, request: &'r Request<'_>) -> BoxFuture<'r> {
    if let Some(body) = custom_body(request) {
        return finish_owned(status, body, None);
    }
    let message = match refusal_verdict(request) {
        // Unreachable: the only `401` producer is the headers/auth stage
        // block, which always records the stage body first, so the
        // custom-body branch above returns before this arm. The arm stays
        // for defense against a future `401` verdict without a body.
        #[cfg(not(coverage))]
        Some(Verdict::AuthRequired) => AUTHENTICATION_REQUIRED_MESSAGE,
        _ => DEFAULT_401,
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
        // A stage block's resolved body rides the block-body slot (read
        // above); the plain family default is the fallback.
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
    // Both slots are read: the enforced slot mirrors the metadata one, and a
    // guard refusal always records exactly one of the two.
    let metadata = metadata_verdict(request);
    let enforced = enforced_verdict(request);
    let guard_caused =
        metadata == Some(Verdict::RedisUnavailable) || enforced == Some(Verdict::RedisUnavailable);
    let emergency =
        metadata == Some(Verdict::EmergencyBlocked) || enforced == Some(Verdict::EmergencyBlocked);
    let message = if guard_caused {
        REDIS_UNAVAILABLE_MESSAGE
    } else if emergency {
        EMERGENCY_MESSAGE
    } else {
        DEFAULT_503
    };
    finish(status, message, None)
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
        Verdict::IpBlocked | Verdict::StageForbidden => {
            plain_response(Status::Forbidden, FORBIDDEN_MESSAGE)
        }
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
        Verdict::EmergencyBlocked => plain_response(Status::ServiceUnavailable, EMERGENCY_MESSAGE),
        Verdict::HeadersBlocked => plain_response(Status::BadRequest, DEFAULT_400),
        Verdict::AuthRequired => {
            plain_response(Status::Unauthorized, AUTHENTICATION_REQUIRED_MESSAGE)
        }
        Verdict::CustomBlock(status) => plain_response(
            Status::from_code(status).unwrap_or(Status::InternalServerError),
            DEFAULT_403,
        ),
        Verdict::HttpsRedirect => plain_response(Status::MovedPermanently, ""),
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
    use rocket::get;

    // An `Err(Status)` from a route is an error outcome: only then do the
    // catchers fire, and none of these requests carry adapter state, so
    // every catcher takes its default-body branch.
    #[get("/400")]
    fn r400() -> Result<(), Status> {
        Err(Status::BadRequest)
    }
    #[get("/403")]
    fn r403() -> Result<(), Status> {
        Err(Status::Forbidden)
    }
    #[get("/429")]
    fn r429() -> Result<(), Status> {
        Err(Status::TooManyRequests)
    }
    #[get("/500")]
    fn r500() -> Result<(), Status> {
        Err(Status::InternalServerError)
    }
    #[get("/503")]
    fn r503() -> Result<(), Status> {
        Err(Status::ServiceUnavailable)
    }

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
        let response = verdict_response_plain(Verdict::Failed);
        assert_eq!(response.status(), Status::InternalServerError);
        assert_eq!(
            response.headers().get_one("Content-Type"),
            Some("text/plain; charset=utf-8")
        );
    }

    #[test]
    fn verdict_response_covers_the_remaining_block_shapes() {
        let response = verdict_response_plain(Verdict::EmergencyBlocked);
        assert_eq!(response.status(), Status::ServiceUnavailable);
        let response = verdict_response_plain(Verdict::HeadersBlocked);
        assert_eq!(response.status(), Status::BadRequest);
        let response = verdict_response_plain(Verdict::AuthRequired);
        assert_eq!(response.status(), Status::Unauthorized);
        let response = verdict_response_plain(Verdict::CustomBlock(418));
        assert_eq!(
            response.status(),
            Status::from_code(418).expect("418 assigns")
        );
    }

    #[get("/authed")]
    fn authed(_guard: crate::BlockGuard) -> &'static str {
        "ok"
    }

    /// An authentication refusal carries the stage's body in the block-body
    /// slot, and the `401` catcher renders that body instead of the minimal
    /// default: the headers/auth stage refuses the route, the guard maps
    /// the verdict to the `401` error outcome, and the catcher finds the
    /// recorded body.
    #[rocket::async_test]
    async fn authentication_refusal_renders_the_stage_body_through_the_401_catcher() {
        use guard_core_engine::headers_auth::HeaderAuthRules;
        use guard_core_rs::headers_auth::{HeadersAuthStage, RouteGuard};
        use rocket::local::asynchronous::Client;
        use rocket::routes;
        use std::sync::Arc;

        let stage = HeadersAuthStage::new(
            None,
            Arc::new(|path| {
                (path == "/authed").then(|| {
                    Arc::new(RouteGuard {
                        rules: HeaderAuthRules {
                            auth_required: Some(String::from("bearer")),
                            ..HeaderAuthRules::default()
                        },
                        verifier: Some(Arc::new(|credential: &str| credential == "t")),
                        api_key_verifier: None,
                    })
                })
            }),
        );
        let fairing = crate::GuardFairing::with_defaults().with_headers_auth(stage);
        let client = Client::tracked(rocket::build().attach(fairing).mount("/", routes![authed]))
            .await
            .expect("valid rocket");

        let response = client.get("/authed").dispatch().await;
        assert_eq!(response.status(), Status::Unauthorized);
        let rendered = response.into_string().await.unwrap_or_default();
        assert_eq!(rendered, AUTHENTICATION_REQUIRED_MESSAGE);

        // The authenticated view of the same route: the stage passes and
        // the handler runs.
        let response = client
            .get("/authed")
            .header(rocket::http::Header::new("Authorization", "Bearer t"))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.into_string().await.as_deref(), Some("ok"));
    }

    /// A catcher that fires without any adapter state on the request falls
    /// back to the minimal default body: each status is produced by a plain
    /// route (no guards, no stashed verdicts) so the unscoped path runs.
    #[rocket::async_test]
    async fn catchers_without_adapter_state_render_the_default_bodies() {
        use rocket::local::asynchronous::Client;
        use rocket::routes;

        let app = rocket::build()
            .mount("/", routes![r400, r403, r429, r500, r503])
            .register("/", guard_catchers());
        let client = Client::tracked(app).await.expect("client");

        let cases = [
            ("/400", (Status::BadRequest, DEFAULT_400)),
            ("/403", (Status::Forbidden, DEFAULT_403)),
            ("/429", (Status::TooManyRequests, DEFAULT_429)),
            ("/500", (Status::InternalServerError, DEFAULT_500)),
            ("/503", (Status::ServiceUnavailable, DEFAULT_503)),
        ];
        for (path, (status, body)) in cases {
            let response = client.get(path).dispatch().await;
            assert_eq!(response.status(), status);
            let rendered = response.into_string().await.unwrap_or_default();
            assert_eq!(rendered, body, "default body for {path}");
        }
    }
}
