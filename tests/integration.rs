//! End-to-end behavior of the public API: fairing + guards on a real
//! application, exercised with Rocket's async local client.

use rocket::catch;
use rocket::catchers;
use rocket::get;
use rocket::http::{Header, Status};
use rocket::local::asynchronous::{Client, LocalResponse};
use rocket::post;
use rocket::routes;
use rocket_guard_rs::{BLOCKED_MESSAGE, BlockGuard, GuardBody, OVERSIZE_MESSAGE};
use rocket_guard_rs::{GuardFairing, default_config};
use std::path::PathBuf;
use std::sync::Arc;

async fn body_text(response: LocalResponse<'_>) -> String {
    response.into_string().await.unwrap_or_default()
}

/// The application under test. The catch-all GET route proves that metadata
/// blocks happen before any handler runs; the POST echo route proves that
/// `GuardBody` hands the intact bytes to the handler on clean requests.
fn app(fairing: GuardFairing) -> rocket::Rocket<rocket::Build> {
    rocket::build()
        .attach(fairing)
        .mount("/", routes![index, catch_all, echo])
}

/// Like [`app`], but without the catch-all route, so unmatched paths really
/// are unmatched (exercising the fairing's `on_response` rewrite).
fn minimal_app(fairing: GuardFairing) -> rocket::Rocket<rocket::Build> {
    rocket::build()
        .attach(fairing)
        .mount("/", routes![index, echo])
}

#[get("/")]
fn index(_guard: BlockGuard) -> &'static str {
    "index"
}

#[get("/<path..>")]
#[allow(clippy::needless_pass_by_value)] // route parameters are owned by design
fn catch_all(path: PathBuf, _guard: BlockGuard) -> String {
    format!("GET /{}", path.display())
}

#[post("/echo", data = "<body>")]
#[allow(clippy::needless_pass_by_value)] // data guards take `Data` by value
fn echo(body: GuardBody) -> String {
    String::from_utf8_lossy(body.as_ref()).into_owned()
}

async fn guarded_client() -> Client {
    Client::tracked(app(GuardFairing::new(default_config())))
        .await
        .expect("valid rocket")
}

#[tokio::test]
async fn benign_request_passes_through_untouched() {
    let client = guarded_client().await;
    let response = client
        .get("/api/items?limit=5")
        .header(Header::new("x-custom", "hello"))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(body_text(response).await, "GET /api/items");
}

#[tokio::test]
async fn xss_payload_in_body_is_blocked() {
    let client = guarded_client().await;
    let response = client
        .post("/echo")
        .body("<script>alert(1)</script>")
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::BadRequest);
    assert_eq!(
        response.headers().get_one("Content-Type"),
        Some("text/plain; charset=utf-8"),
    );
    assert_eq!(body_text(response).await, BLOCKED_MESSAGE);
}

#[tokio::test]
async fn traversal_payload_in_path_is_blocked() {
    let client = guarded_client().await;
    let response = client.get("/files/../../etc/passwd").dispatch().await;
    assert_eq!(response.status(), Status::BadRequest);
    assert_eq!(body_text(response).await, BLOCKED_MESSAGE);
}

#[tokio::test]
async fn command_injection_in_query_is_blocked() {
    // Raw spaces are invalid in a URI, so the payload travels percent-encoded
    // and the engine's preprocessor decodes it back to `$(echo id)`.
    let client = guarded_client().await;
    let response = client.get("/search?cmd=$(echo%20id)").dispatch().await;
    assert_eq!(response.status(), Status::BadRequest);
    assert_eq!(body_text(response).await, BLOCKED_MESSAGE);
}

#[tokio::test]
async fn xss_payload_in_scanned_header_is_blocked() {
    let client = guarded_client().await;
    let response = client
        .get("/")
        .header(Header::new("x-comment", "<script>alert(1)</script>"))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::BadRequest);
}

#[tokio::test]
async fn excluded_headers_are_never_scanned() {
    // `User-Agent` is on the exclusion list, so even a value that looks like a
    // payload is not fed to the engine. This pins the documented policy.
    let client = guarded_client().await;
    let response = client
        .get("/")
        .header(Header::new("user-agent", "<script>alert(1)</script>"))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
}

#[tokio::test]
async fn body_over_the_cap_is_rejected_with_413() {
    let fairing = GuardFairing::with_defaults().with_body_cap(16);
    let client = Client::tracked(app(fairing)).await.expect("valid rocket");
    let response = client
        .post("/echo")
        .body("this body is much longer than sixteen bytes")
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::PayloadTooLarge);
    assert_eq!(body_text(response).await, OVERSIZE_MESSAGE);
}

#[tokio::test]
async fn body_at_the_cap_is_forwarded_intact() {
    let fairing = GuardFairing::with_defaults().with_body_cap(16);
    let client = Client::tracked(app(fairing)).await.expect("valid rocket");
    let response = client
        .post("/echo")
        .body("exactly-16-bytes")
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(body_text(response).await, "exactly-16-bytes");
}

#[tokio::test]
async fn unrouted_threat_path_gets_the_guarded_400_not_a_404() {
    // No route matches `/private/...`; a plain 404 would leak that, so the
    // fairing's on_response rewrite answers the guarded 400 instead.
    let client = Client::tracked(minimal_app(GuardFairing::new(default_config())))
        .await
        .expect("valid rocket");
    let response = client.get("/private/../../etc/passwd").dispatch().await;
    assert_eq!(response.status(), Status::BadRequest);
    assert_eq!(body_text(response).await, BLOCKED_MESSAGE);
}

#[tokio::test]
async fn unrouted_benign_path_still_404s() {
    // The rewrite must be threat-scoped, not a blanket 404 replacement.
    let client = Client::tracked(minimal_app(GuardFairing::new(default_config())))
        .await
        .expect("valid rocket");
    let response = client.get("/definitely/not/mounted").dispatch().await;
    assert_eq!(response.status(), Status::NotFound);
}

#[tokio::test]
async fn guard_without_the_fairing_fails_secure() {
    // No fairing: no verdict is stashed, so the guard refuses instead of
    // passing the request uninspected. The catchers are not registered
    // either, so only the status is asserted here.
    let client = Client::tracked(rocket::build().mount("/", routes![index]))
        .await
        .expect("valid rocket");
    let response = client.get("/").dispatch().await;
    assert_eq!(response.status(), Status::InternalServerError);
}

#[tokio::test]
async fn user_catcher_takes_precedence_and_launch_stays_collision_free() {
    // The fairing must skip registering over an application catcher (Rocket
    // treats same-code catchers at the same base as a fatal collision), and
    // the application's catcher then renders guard refusals.
    #[catch(400)]
    fn my_bad_request() -> &'static str {
        "custom bad request"
    }

    let client = Client::tracked(
        rocket::build()
            .attach(GuardFairing::new(default_config()))
            .register("/", catchers![my_bad_request])
            .mount("/", routes![index, catch_all, echo]),
    )
    .await
    .expect("valid rocket: catcher collisions are avoided by skipping");

    let response = client.get("/files/../../etc/passwd").dispatch().await;
    assert_eq!(response.status(), Status::BadRequest);
    assert_eq!(body_text(response).await, "custom bad request");
}

#[tokio::test]
async fn concurrent_requests_are_screened_independently() {
    let client = Arc::new(guarded_client().await);

    let handles: Vec<_> = (0..24)
        .map(|index| {
            let client = Arc::clone(&client);
            tokio::spawn(async move {
                if index % 2 == 0 {
                    client.get("/health").dispatch().await.status()
                } else {
                    client
                        .post("/echo")
                        .body("<script>alert(1)</script>")
                        .dispatch()
                        .await
                        .status()
                }
            })
        })
        .collect();

    for (index, handle) in handles.into_iter().enumerate() {
        let status = handle.await.expect("task");
        if index % 2 == 0 {
            assert_eq!(status, Status::Ok, "benign request {index}");
        } else {
            assert_eq!(status, Status::BadRequest, "threat request {index}");
        }
    }
}
