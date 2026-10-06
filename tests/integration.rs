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
use std::sync::{Arc, Mutex};

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

#[tokio::test]
async fn valueless_query_parameter_is_benign() {
    // A query pair without `=` (`?flag`) is a name with an empty value; it
    // must decode and scan like any other pair, not fall over.
    let client = guarded_client().await;
    let response = client.get("/api/items?flag").dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(body_text(response).await, "GET /api/items");
}

#[tokio::test]
async fn whitespace_only_body_passes_unscanned() {
    let client = guarded_client().await;
    let response = client.post("/echo").body("   \n\t").dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(body_text(response).await, "   \n\t");
}

#[tokio::test]
async fn metadata_threat_blocks_the_body_guard_before_the_scan() {
    // The query already trips the metadata pass, so the `GuardBody` route
    // refuses on the stashed verdict without even reading the (benign) body.
    let client = guarded_client().await;
    let response = client
        .post("/echo?q=1+OR+1%3D1")
        .body("perfectly innocent")
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::BadRequest);
    assert_eq!(body_text(response).await, BLOCKED_MESSAGE);
}

#[post("/reveal", data = "<body>")]
#[allow(clippy::needless_pass_by_value)] // data guards take `Data` by value
fn reveal(body: GuardBody) -> String {
    format!(
        "{} bytes: {}",
        body.as_slice().len(),
        String::from_utf8_lossy(&body.into_inner())
    )
}

#[tokio::test]
async fn guard_hands_the_scanned_bytes_to_the_handler() {
    // Both byte accessors on the scanned body: `as_slice` before the move,
    // `into_inner` after, with the bytes intact end to end.
    let client = Client::tracked(
        rocket::build()
            .attach(GuardFairing::new(default_config()))
            .mount("/", routes![reveal]),
    )
    .await
    .expect("valid rocket");
    let response = client.post("/reveal").body("hello").dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(body_text(response).await, "5 bytes: hello");
}

// --- the catcher defaults: statuses the application raises itself ---

#[get("/bad-request")]
fn bad_request_route() -> Status {
    Status::BadRequest
}

#[get("/forbidden")]
fn forbidden_route() -> Status {
    Status::Forbidden
}

#[get("/too-many-requests")]
fn too_many_requests_route() -> Status {
    Status::TooManyRequests
}

#[get("/service-unavailable")]
fn service_unavailable_route() -> Status {
    Status::ServiceUnavailable
}

#[get("/server-error")]
fn server_error_route() -> Status {
    Status::InternalServerError
}

#[tokio::test]
async fn application_error_statuses_keep_the_minimal_default_bodies() {
    // A `4xx`/`5xx` the application raises itself (clean request, no guard
    // refusal) must not be dressed up as a guard verdict: the catchers fall
    // back to the minimal default body per status.
    let client = Client::tracked(
        rocket::build()
            .attach(GuardFairing::new(default_config()))
            .mount(
                "/",
                routes![
                    bad_request_route,
                    forbidden_route,
                    too_many_requests_route,
                    service_unavailable_route,
                    server_error_route,
                ],
            ),
    )
    .await
    .expect("valid rocket");

    let expectations: [(&str, Status, &str); 5] = [
        ("/bad-request", Status::BadRequest, "400 Bad Request"),
        ("/forbidden", Status::Forbidden, "403 Forbidden"),
        (
            "/too-many-requests",
            Status::TooManyRequests,
            "429 Too Many Requests",
        ),
        (
            "/service-unavailable",
            Status::ServiceUnavailable,
            "503 Service Unavailable",
        ),
        (
            "/server-error",
            Status::InternalServerError,
            "500 Internal Server Error",
        ),
    ];
    for (path, status, body) in expectations {
        let response = client.get(path).dispatch().await;
        assert_eq!(response.status(), status, "{path}");
        assert_eq!(body_text(response).await, body, "{path}");
    }
}

// --- the request-local overrides, set by a preceding fairing ---

/// A fairing attached before `GuardFairing` that pins a one-request tier on
/// every route: the documented attach-order way to resolve the per-route
/// rate limit ahead of the security pass.
struct TierOverride;

#[rocket::async_trait]
impl rocket::fairing::Fairing for TierOverride {
    fn info(&self) -> rocket::fairing::Info {
        rocket::fairing::Info {
            name: "TierOverride",
            kind: rocket::fairing::Kind::Request,
        }
    }

    async fn on_request(&self, request: &mut rocket::Request<'_>, _data: &mut rocket::Data<'_>) {
        rocket_guard_rs::set_route_rate_limits(
            request,
            rocket_guard_rs::RouteRateLimits::new(Some(1), None, None).expect("valid tiers"),
        );
    }
}

#[tokio::test]
async fn request_local_route_tiers_limit_their_request() {
    let fairing = GuardFairing::with_defaults().with_rate_limiting(
        rocket_guard_rs::RateLimiter::new(rocket_guard_rs::RateLimitConfig {
            enable_rate_limiting: true,
            rate_limit: 1000,
            rate_limit_window: 60,
            ..rocket_guard_rs::RateLimitConfig::default()
        })
        .expect("valid config"),
    );
    let client = Client::tracked(
        rocket::build()
            .attach(TierOverride)
            .attach(fairing)
            .mount("/", routes![index]),
    )
    .await
    .expect("valid rocket");
    let response = client
        .get("/")
        .remote("192.0.2.91:1000".parse().unwrap())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let response = client
        .get("/")
        .remote("192.0.2.91:1000".parse().unwrap())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::TooManyRequests);
    assert_eq!(
        response.headers().get_one("Retry-After"),
        Some("60"),
        "the override tier's window decides"
    );
}

/// A fairing attached before `GuardFairing` that excludes the `q` query
/// parameter on every route: the documented attach-order way to resolve the
/// per-route detection exclusions ahead of the scan.
struct ExclusionsOverride;

#[rocket::async_trait]
impl rocket::fairing::Fairing for ExclusionsOverride {
    fn info(&self) -> rocket::fairing::Info {
        rocket::fairing::Info {
            name: "ExclusionsOverride",
            kind: rocket::fairing::Kind::Request,
        }
    }

    async fn on_request(&self, request: &mut rocket::Request<'_>, _data: &mut rocket::Data<'_>) {
        rocket_guard_rs::set_route_detection_exclusions(
            request,
            rocket_guard_rs::RouteDetectionExclusions {
                excluded_detection_params: Some(vec!["q".to_owned()]),
                ..rocket_guard_rs::RouteDetectionExclusions::default()
            },
        );
    }
}

#[tokio::test]
async fn request_local_route_exclusions_skip_their_surface() {
    let client = Client::tracked(
        rocket::build()
            .attach(ExclusionsOverride)
            .attach(GuardFairing::new(default_config()))
            .mount("/", routes![index]),
    )
    .await
    .expect("valid rocket");
    let response = client
        .get("/?q=1+OR+1%3D1")
        .remote("192.0.2.92:1000".parse().unwrap())
        .dispatch()
        .await;
    assert_eq!(
        response.status(),
        Status::Ok,
        "the route excludes the param"
    );
}

// The newly wired stage surface (the reference 17-check pipeline): every
// test below installs one stage on the fairing and proves its end-to-end
// shape through the real Rocket stack (fairing + guards + catchers).

use guard_core_engine::behavior::BehaviorTracker;
use guard_core_engine::cors::CorsConfig;
use guard_core_engine::custom_checks::{
    CustomRequestContext, CustomResponse, CustomValidatorFn, ValidatorAnswer,
};
use guard_core_engine::geo::{GeoIpHandler, parse_country_lists};
use guard_core_engine::headers_auth::{HeaderAuthRules, REQUIRED_SENTINEL, RequiredHeader};
use guard_core_engine::ip_ban::IpBanManager;
use guard_core_engine::security_headers::SecurityHeadersConfig;
use guard_core_rs::cloud_provider::{
    CloudIpTable, CloudProviderStage, CloudProviderStageConfig, parse_cloud_selectors,
};
use guard_core_rs::custom_checks::CustomChecksStage;
use guard_core_rs::emergency_mode::EmergencyModeStage;
use guard_core_rs::geo::{GeoStage, GeoStageConfig};
use guard_core_rs::headers_auth::{HeadersAuthStage, RouteGuard};
use guard_core_rs::https_enforcement::{HttpsEnforcementStage, HttpsEnforcementStageConfig};
use guard_core_rs::process_response::ResponseProcessor;
use guard_core_rs::route_gates::{GateConfig, ReferrerStage, TimeWindowStage};
use guard_core_rs::user_agent::{UserAgentFilter, UserAgentStage, UserAgentStageConfig};

struct UnitedStates;

impl GeoIpHandler for UnitedStates {
    fn get_country(&self, ip: std::net::IpAddr) -> Option<String> {
        (ip.to_string() == "192.0.2.9").then(|| String::from("US"))
    }
}

#[tokio::test]
async fn emergency_mode_blocks_outside_the_whitelist() {
    let stage = EmergencyModeStage::builder(
        guard_core_rs::emergency_mode::EmergencyModeStageConfig::default(),
    )
    .emergency_mode(true)
    .emergency_whitelist(["203.0.113.9"])
    .build()
    .expect("valid whitelist");
    let client = Client::tracked(app(
        GuardFairing::new(default_config()).with_emergency_mode(stage)
    ))
    .await
    .expect("valid rocket");

    let response = client
        .get("/api/items")
        .remote("198.51.100.1:1000".parse().unwrap())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::ServiceUnavailable);
    assert_eq!(body_text(response).await, "Service temporarily unavailable");

    let response = client
        .get("/api/items")
        .remote("203.0.113.9:1000".parse().unwrap())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(body_text(response).await, "GET /api/items");
}

#[tokio::test]
async fn https_enforcement_redirects_plain_http() {
    let stage = HttpsEnforcementStage::builder(HttpsEnforcementStageConfig::default())
        .enforce_https(true)
        .build()
        .expect("valid");
    let client = Client::tracked(app(
        GuardFairing::new(default_config()).with_https_enforcement(stage)
    ))
    .await
    .expect("valid rocket");

    let response = client
        .get("/private?token=1")
        .header(Header::new("Host", "guard.example"))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::MovedPermanently);
    assert_eq!(
        response.headers().get_one("Location"),
        Some("https://guard.example/private?token=1")
    );
}

#[tokio::test]
async fn required_headers_and_authentication_answer_the_reference_shapes() {
    let stage = HeadersAuthStage::new(
        None,
        Arc::new(|path: &str| {
            (path == "/private").then(|| {
                Arc::new(RouteGuard {
                    rules: HeaderAuthRules {
                        required_headers: vec![RequiredHeader {
                            name: String::from("x-api-key"),
                            expected: String::from(REQUIRED_SENTINEL),
                        }],
                        auth_required: Some(String::from("bearer")),
                        ..HeaderAuthRules::default()
                    },
                    verifier: Some(Arc::new(|credential: &str| credential == "let-me-in")),
                    api_key_verifier: None,
                })
            })
        }),
    );
    let client = Client::tracked(app(
        GuardFairing::new(default_config()).with_headers_auth(stage)
    ))
    .await
    .expect("valid rocket");

    // The required header is missing: the reference dynamic `400` shape.
    let response = client.get("/private").dispatch().await;
    assert_eq!(response.status(), Status::BadRequest);

    // The header is present but the bearer credential is wrong: `401`.
    let response = client
        .get("/private")
        .header(Header::new("x-api-key", "present"))
        .header(Header::new("Authorization", "Bearer nope"))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Unauthorized);
    assert_eq!(body_text(response).await, "Authentication required");

    // Both rules pass: the handler runs.
    let response = client
        .get("/private")
        .header(Header::new("x-api-key", "present"))
        .header(Header::new("Authorization", "Bearer let-me-in"))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
}

#[tokio::test]
async fn referrer_gate_blocks_a_missing_or_foreign_referrer() {
    let stage = ReferrerStage::builder(GateConfig::default())
        .resolver(Arc::new(|path: &str| {
            (path == "/gated").then(|| vec![String::from("https://good.example")])
        }))
        .build();
    let client = Client::tracked(app(
        GuardFairing::new(default_config()).with_referrer_gate(stage)
    ))
    .await
    .expect("valid rocket");

    let response = client.get("/gated").dispatch().await;
    assert_eq!(response.status(), Status::Forbidden);
    assert_eq!(body_text(response).await, "Referrer required");

    let response = client
        .get("/gated")
        .header(Header::new("Referer", "https://good.example/page"))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);

    let response = client
        .get("/gated")
        .header(Header::new("Referer", "https://evil.example/page"))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Forbidden);
    assert_eq!(body_text(response).await, "Invalid referrer");
}

#[tokio::test]
async fn custom_validators_block_with_the_validator_response() {
    let stage = CustomChecksStage::builder()
        .validators_resolver(Arc::new(|path: &str| {
            (path == "/private").then(|| {
                vec![(
                    String::from("post_only"),
                    Arc::new(|ctx: &CustomRequestContext<'_>| {
                        (ctx.method != "POST").then_some(ValidatorAnswer::Response(
                            CustomResponse { status: Some(403) },
                        ))
                    }) as CustomValidatorFn,
                )]
            })
        }))
        .build();
    let client = Client::tracked(app(
        GuardFairing::new(default_config()).with_custom_checks(stage)
    ))
    .await
    .expect("valid rocket");

    let response = client.get("/private").dispatch().await;
    assert_eq!(response.status(), Status::Forbidden);

    let response = client.post("/echo").body("{}").dispatch().await;
    assert_eq!(response.status(), Status::Ok);
}

#[tokio::test]
async fn time_window_gate_blocks_outside_the_window() {
    // The window is computed from the live clock so the test is
    // deterministic: the gate closes for everything except a two-minute
    // band that starts two minutes from now.
    let now = chrono::Utc::now();
    let start = (now + chrono::Duration::minutes(2))
        .format("%H:%M")
        .to_string();
    let end = (now + chrono::Duration::minutes(3))
        .format("%H:%M")
        .to_string();
    let stage = TimeWindowStage::builder(GateConfig::default())
        .resolver(Arc::new(move |path: &str| {
            (path == "/nightly").then(|| guard_core_engine::time_window::TimeWindow {
                start: Some(start.clone()),
                end: Some(end.clone()),
                timezone: Some(String::from("UTC")),
            })
        }))
        .build();
    let client = Client::tracked(app(
        GuardFairing::new(default_config()).with_time_window_gate(stage)
    ))
    .await
    .expect("valid rocket");

    let response = client.get("/nightly").dispatch().await;
    assert_eq!(response.status(), Status::Forbidden);
    assert_eq!(body_text(response).await, "Access not allowed at this time");

    let response = client.get("/open").dispatch().await;
    assert_eq!(response.status(), Status::Ok);
}

#[tokio::test]
async fn cloud_provider_blocking_answers_the_reference_403() {
    let table = CloudIpTable::default();
    table
        .set_provider_ranges("AWS", vec![(String::from("192.0.2.0/24"), None)])
        .expect("valid ranges");
    let stage = CloudProviderStage::new(CloudProviderStageConfig {
        block_cloud_providers: parse_cloud_selectors(["AWS"]).expect("valid selectors"),
        table,
        passive_mode: false,
    });
    let client = Client::tracked(app(
        GuardFairing::new(default_config()).with_cloud_provider(stage)
    ))
    .await
    .expect("valid rocket");

    let response = client
        .get("/api")
        .remote("192.0.2.9:1000".parse().unwrap())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Forbidden);
    assert_eq!(body_text(response).await, "Cloud provider IP not allowed");

    let response = client
        .get("/api")
        .remote("198.51.100.9:1000".parse().unwrap())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
}

#[tokio::test]
async fn geo_country_blocking_answers_the_reference_403() {
    let stage = GeoStage::new(GeoStageConfig {
        gate: parse_country_lists(Vec::<String>::new(), ["US"]),
        handler: Some(Arc::new(UnitedStates)),
        passive_mode: false,
    });
    let client = Client::tracked(app(
        GuardFairing::new(default_config()).with_geo_blocking(stage)
    ))
    .await
    .expect("valid rocket");

    let response = client
        .get("/api")
        .remote("192.0.2.9:1000".parse().unwrap())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Forbidden);
    assert_eq!(body_text(response).await, "Forbidden");

    let response = client
        .get("/api")
        .remote("198.51.100.9:1000".parse().unwrap())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
}

#[tokio::test]
async fn user_agent_blocking_answers_the_reference_403() {
    let stage = UserAgentStage::new(UserAgentStageConfig {
        blocked_user_agents: UserAgentFilter::new(["bad-bot"]).expect("valid patterns"),
        ..UserAgentStageConfig::default()
    })
    .expect("valid config");
    let client = Client::tracked(app(
        GuardFairing::new(default_config()).with_user_agent(stage)
    ))
    .await
    .expect("valid rocket");

    let response = client
        .get("/api")
        .header(Header::new("User-Agent", "bad-bot/1.0"))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Forbidden);
    assert_eq!(body_text(response).await, "User-Agent not allowed");

    let response = client
        .get("/api")
        .header(Header::new("User-Agent", "friendly-crawler/2.0"))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
}

#[tokio::test]
async fn custom_request_blocks_with_the_function_response() {
    let stage = CustomChecksStage::builder()
        .custom_request(
            "maintenance_gate",
            Arc::new(|ctx: &CustomRequestContext<'_>| {
                (ctx.path == "/admin").then_some(CustomResponse { status: Some(503) })
            }),
        )
        .build();
    let client = Client::tracked(app(
        GuardFairing::new(default_config()).with_custom_checks(stage)
    ))
    .await
    .expect("valid rocket");

    let response = client.get("/admin").dispatch().await;
    assert_eq!(response.status(), Status::ServiceUnavailable);

    let response = client.get("/public").dispatch().await;
    assert_eq!(response.status(), Status::Ok);
}

#[tokio::test]
async fn response_processor_renders_security_headers_and_cors_on_every_response() {
    let processor = ResponseProcessor::new(
        Some(SecurityHeadersConfig::reference_default()),
        Some(CorsConfig {
            enabled: true,
            allow_origins: vec![String::from("https://app.example.com")],
            ..CorsConfig::default()
        }),
        Vec::new(),
        Arc::new(Mutex::new(BehaviorTracker::new())),
        IpBanManager::new(),
        true,
        262_144,
        false,
    );
    let client = Client::tracked(app(
        GuardFairing::new(default_config()).with_response_processor(processor)
    ))
    .await
    .expect("valid rocket");

    let response = client
        .get("/api")
        .header(Header::new("Origin", "https://app.example.com"))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(
        response.headers().get_one("x-content-type-options"),
        Some("nosniff")
    );
    assert_eq!(
        response.headers().get_one("access-control-allow-origin"),
        Some("https://app.example.com")
    );

    // Block answers carry the set too (headers on blocked + passthrough).
    let response = client
        .post("/echo")
        .body("<script>alert(1)</script>")
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::BadRequest);
    assert_eq!(
        response.headers().get_one("x-frame-options"),
        Some("SAMEORIGIN")
    );
}

#[tokio::test]
async fn request_logging_composes_without_blocking() {
    let stage = guard_core_rs::request_logging::RequestLoggingStage::new(
        guard_core_rs::request_logging::RequestLoggingStageConfig::default(),
    );
    let client = Client::tracked(app(
        GuardFairing::new(default_config()).with_request_logging(stage)
    ))
    .await
    .expect("valid rocket");

    let response = client.get("/api/items?limit=5").dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(body_text(response).await, "GET /api/items");
}
