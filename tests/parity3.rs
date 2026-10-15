//! Reference parity, third wave: the route usage rules run after the whole
//! pipeline, the live config reaches the stages a dynamic rule can change,
//! `route_resolution_strict`, and the request-body `body_read_timeout`.
//!
//! Everything here drives the public surface only.

use guard_core_engine::behavior::{BehaviorRule, BehaviorTracker};
use guard_core_engine::geo::GeoIpHandler;
use guard_core_engine::route_config::{RouteConfig, RouteConfigResolver};
use guard_core_engine::security_config::SecurityConfig;
use guard_core_rs::events::{SecurityEvent, SecurityEventBus};
use guard_core_rs::process_response::ResponseProcessor;
use rocket::http::{ContentType, Header, Status};
use rocket::local::asynchronous::{Client, LocalResponse};
use rocket::{get, post, routes};
use rocket_guard_rs::{BlockGuard, GuardBody, GuardFairing, IpBanManager, OnBlockHook, Wiring};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};

#[get("/hello")]
fn hello(_guard: BlockGuard) -> &'static str {
    "ok"
}

#[get("/open")]
fn open() -> &'static str {
    "open"
}

#[get("/forwarded")]
fn forwarded_scoped(_scoped: rocket_guard_rs::GuardExclusionScoped) -> &'static str {
    "scoped"
}

#[post("/post", data = "<body>")]
fn post_body(body: GuardBody) -> Vec<u8> {
    body.into_inner()
}

/// A script injection in the query string of a guarded route.
const ATTACK: &str = "/hello?q=%3Cscript%3Ealert(1)%3C/script%3E";

async fn client(fairing: GuardFairing) -> Client {
    Client::tracked(
        rocket::build()
            .attach(fairing)
            .mount("/", routes![hello, open, post_body]),
    )
    .await
    .expect("valid rocket")
}

fn peer(last: u8) -> SocketAddr {
    SocketAddr::new(IpAddr::from([192, 0, 2, last]), 45_000)
}

async fn status_of(response: LocalResponse<'_>) -> (Status, String) {
    let status = response.status();
    (status, response.into_string().await.unwrap_or_default())
}

fn config() -> SecurityConfig {
    SecurityConfig {
        enable_redis: false,
        ..SecurityConfig::default()
    }
}

// --- usage rules run after the pipeline ---

fn usage_resolver(path: &'static str) -> RouteConfigResolver {
    let route = Arc::new(RouteConfig {
        behavior_rules: vec![BehaviorRule {
            rule_type: String::from("usage"),
            threshold: 2,
            window: 60,
            pattern: String::new(),
            action: String::from("ban"),
            ban_duration: Some(3600),
            correlate_with_detection: false,
        }],
        ..RouteConfig::default()
    });
    Arc::new(move |_method: &str, request_path: &str| {
        (request_path == path).then(|| Arc::clone(&route))
    })
}

fn usage_processor(manager: &IpBanManager) -> ResponseProcessor {
    ResponseProcessor::new(
        None,
        None,
        Vec::new(),
        Arc::new(Mutex::new(BehaviorTracker::new())),
        manager.clone(),
        true,
        262_144,
        false,
    )
}

fn usage_fairing(path: &'static str, manager: &IpBanManager) -> GuardFairing {
    GuardFairing::with_defaults()
        .with_response_processor(usage_processor(manager))
        .with_route_configs(usage_resolver(path))
}

#[tokio::test]
async fn usage_rules_do_not_count_a_request_the_pipeline_blocked() {
    let manager = IpBanManager::new();
    let client = client(usage_fairing("/hello", &manager)).await;
    // Three attacks the pipeline refuses: the reference never reaches
    // `process_usage_rules` for them.
    for _ in 0..3 {
        let response = client.get(ATTACK).remote(peer(81)).dispatch().await;
        assert_eq!(response.status(), Status::BadRequest);
    }
    // The first request that passes is the first observation (threshold 2).
    let (status, body) = status_of(client.get("/hello").remote(peer(81)).dispatch().await).await;
    assert_eq!((status, body.as_str()), (Status::Ok, "ok"));
}

#[tokio::test]
async fn usage_rules_ban_at_the_threshold_for_a_guarded_route() {
    let manager = IpBanManager::new();
    let client = client(usage_fairing("/hello", &manager)).await;
    for _ in 0..2 {
        let (status, _) = status_of(client.get("/hello").remote(peer(82)).dispatch().await).await;
        assert_eq!(status, Status::Ok);
    }
    let (status, body) = status_of(client.get("/hello").remote(peer(82)).dispatch().await).await;
    assert_eq!(
        (status, body.as_str()),
        (Status::Forbidden, "IP has been banned")
    );
}

#[tokio::test]
async fn usage_rules_run_once_for_a_route_without_a_guard() {
    let manager = IpBanManager::new();
    let client = client(usage_fairing("/open", &manager)).await;
    for _ in 0..3 {
        let (status, _) = status_of(client.get("/open").remote(peer(83)).dispatch().await).await;
        assert_eq!(status, Status::Ok, "an unguarded route is never refused");
    }
    // The rule fired exactly at the third observation (each request counts once).
    assert!(manager.is_banned(IpAddr::from([192, 0, 2, 83])));
}

#[tokio::test]
async fn usage_rules_wait_for_the_body_scan() {
    let manager = IpBanManager::new();
    let client = client(usage_fairing("/post", &manager)).await;
    for _ in 0..3 {
        let response = client
            .post("/post")
            .remote(peer(84))
            .header(ContentType::Plain)
            .body("<script>alert(1)</script>")
            .dispatch()
            .await;
        assert_eq!(
            response.status(),
            Status::BadRequest,
            "the body scan blocks"
        );
    }
    let response = client
        .post("/post")
        .remote(peer(84))
        .header(ContentType::Plain)
        .body("hello")
        .dispatch()
        .await;
    assert_eq!(
        response.status(),
        Status::Ok,
        "blocked bodies were not counted"
    );
}

#[tokio::test]
async fn usage_rules_skip_an_unattributed_request() {
    let manager = IpBanManager::new();
    let client = client(usage_fairing("/hello", &manager)).await;
    for _ in 0..4 {
        let (status, _) = status_of(client.get("/hello").dispatch().await).await;
        assert_eq!(status, Status::Ok);
    }
}

// --- live config ---

struct UnitedStates;

impl GeoIpHandler for UnitedStates {
    fn get_country(&self, _ip: IpAddr) -> Option<String> {
        Some("US".to_owned())
    }
}

async fn live_client(
    change: impl FnOnce(&mut SecurityConfig),
) -> (Client, Arc<RwLock<SecurityConfig>>) {
    let mut config = config();
    config.geo_ip_handler = Some(Arc::new(UnitedStates));
    change(&mut config);
    let wiring = Wiring::from_security_config(&config).expect("wired");
    let live = Arc::clone(&wiring.live_config);
    (client(GuardFairing::from_wiring(wiring)).await, live)
}

fn rule(live: &Arc<RwLock<SecurityConfig>>, change: impl FnOnce(&mut SecurityConfig)) {
    change(&mut live.write().expect("live config"));
}

#[tokio::test]
async fn a_dynamic_rate_limit_rule_changes_the_live_limit_and_keeps_the_windows() {
    let (client, live) = live_client(|config| {
        config.enable_rate_limiting = true;
        config.rate_limit = 2;
        config.rate_limit_window = 60;
    })
    .await;
    for _ in 0..2 {
        let (status, _) = status_of(client.get("/hello").remote(peer(91)).dispatch().await).await;
        assert_eq!(status, Status::Ok);
    }
    let (status, _) = status_of(client.get("/hello").remote(peer(91)).dispatch().await).await;
    assert_eq!(status, Status::TooManyRequests);

    // A rule raises the limit: the recorded window carries over.
    rule(&live, |config| config.rate_limit = 100);
    let (status, _) = status_of(client.get("/hello").remote(peer(91)).dispatch().await).await;
    assert_eq!(status, Status::Ok);

    // A rule that switches the limiter off stops the 429s.
    rule(&live, |config| {
        config.rate_limit = 1;
        config.enable_rate_limiting = false;
    });
    let (status, _) = status_of(client.get("/hello").remote(peer(91)).dispatch().await).await;
    assert_eq!(status, Status::Ok);
}

async fn attack_status(client: &Client) -> Status {
    client
        .get(ATTACK)
        .remote(peer(92))
        .dispatch()
        .await
        .status()
}

#[tokio::test]
async fn dynamic_country_agent_emergency_and_detection_rules_take_effect() {
    let (client, live) = live_client(|_| {}).await;
    let (status, _) = status_of(client.get("/hello").remote(peer(92)).dispatch().await).await;
    assert_eq!(status, Status::Ok);

    rule(&live, |config| {
        config.blocked_countries = std::collections::BTreeSet::from(["US".to_owned()]);
    });
    let (status, _) = status_of(client.get("/hello").remote(peer(92)).dispatch().await).await;
    assert_eq!(status, Status::Forbidden);
    rule(&live, |config| config.blocked_countries.clear());

    rule(&live, |config| {
        config.blocked_user_agents = vec!["badbot".to_owned()];
    });
    let response = client
        .get("/hello")
        .remote(peer(92))
        .header(Header::new("User-Agent", "badbot/1.0"))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Forbidden);
    rule(&live, |config| config.blocked_user_agents.clear());

    rule(&live, |config| config.emergency_mode = true);
    let (status, _) = status_of(client.get("/hello").remote(peer(92)).dispatch().await).await;
    assert_eq!(status, Status::ServiceUnavailable);
    rule(&live, |config| config.emergency_mode = false);

    assert_eq!(attack_status(&client).await, Status::BadRequest);
    rule(&live, |config| config.enable_penetration_detection = false);
    assert_eq!(attack_status(&client).await, Status::Ok);
    // The body phase reads the same toggle.
    let response = client
        .post("/post")
        .remote(peer(92))
        .header(ContentType::Plain)
        .body("<script>alert(1)</script>")
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
}

#[tokio::test]
async fn a_dynamic_cloud_provider_rule_builds_the_stage() {
    let (client, live) = live_client(|_| {}).await;
    rule(&live, |config| {
        config.block_cloud_providers = Some(std::collections::BTreeSet::from(["AWS".to_owned()]));
    });
    // The range table is empty until a refresh fills it, so nothing blocks,
    // but the request runs through the rebuilt stage.
    let (status, _) = status_of(client.get("/hello").remote(peer(93)).dispatch().await).await;
    assert_eq!(status, Status::Ok);
}

// --- route_resolution_strict ---

fn recording_bus() -> (Arc<SecurityEventBus>, Arc<Mutex<Vec<String>>>) {
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    let bus = SecurityEventBus::new(true).on_event(Arc::new(move |event: &SecurityEvent| {
        // The response pass also reports its security headers.
        if event.event_type == "route_unresolved" {
            sink.lock()
                .expect("sink")
                .push(format!("{}:{}", event.event_type, event.action_taken));
        }
    }));
    (Arc::new(bus), seen)
}

fn strict_config() -> SecurityConfig {
    SecurityConfig {
        route_resolution_strict: true,
        ..config()
    }
}

#[tokio::test]
async fn the_strict_route_resolution_answers_an_unmatched_request() {
    let fairing = GuardFairing::from_security_config(&strict_config()).expect("valid");
    let client = client(fairing).await;
    let (status, body) = status_of(client.get("/nowhere").remote(peer(61)).dispatch().await).await;
    assert_eq!(
        (status, body.as_str()),
        (Status::InternalServerError, "Route resolution failed")
    );
    // A matched route passes, strict or not.
    let (status, _) = status_of(client.get("/hello").remote(peer(61)).dispatch().await).await;
    assert_eq!(status, Status::Ok);

    // The builder installs the same switch on a fairing built from a config
    // that left it off.
    let built = GuardFairing::from_security_config(&config())
        .expect("valid")
        .with_route_resolution_strict(true);
    let built = self::client(built).await;
    let (status, _) = status_of(built.get("/nowhere").remote(peer(61)).dispatch().await).await;
    assert_eq!(status, Status::InternalServerError);

    // Without strict mode the request keeps Rocket's own `404`.
    let lax = GuardFairing::from_security_config(&config()).expect("valid");
    let lax = self::client(lax).await;
    let (status, _) = status_of(lax.get("/nowhere").remote(peer(61)).dispatch().await).await;
    assert_eq!(status, Status::NotFound);
}

#[tokio::test]
async fn a_route_that_matched_and_forwarded_is_not_unresolved() {
    // The guard forwards a request that is not excluded, so Rocket answers `404`
    // from its catcher, but a route did match.
    let fairing = GuardFairing::from_security_config(&strict_config()).expect("valid");
    let client = Client::tracked(
        rocket::build()
            .attach(fairing)
            .mount("/", routes![forwarded_scoped]),
    )
    .await
    .expect("valid rocket");
    let (status, _) = status_of(client.get("/forwarded").remote(peer(62)).dispatch().await).await;
    assert_eq!(
        status,
        Status::NotFound,
        "a matched route is not unresolved"
    );
}

#[tokio::test]
async fn the_strict_route_resolution_honours_a_custom_error_body() {
    let config = SecurityConfig {
        custom_error_responses: [(500u16, "nope".to_owned())].into_iter().collect(),
        ..strict_config()
    };
    let client = client(GuardFairing::from_security_config(&config).expect("valid")).await;
    let (status, body) = status_of(client.get("/nowhere").remote(peer(63)).dispatch().await).await;
    assert_eq!(
        (status, body.as_str()),
        (Status::InternalServerError, "nope")
    );
}

#[tokio::test]
async fn the_strict_route_resolution_is_log_only_under_passive_mode_and_emits_the_event() {
    let (bus, events) = recording_bus();
    let blocks = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&blocks);
    let hook: OnBlockHook = Arc::new(move |payload| {
        sink.lock().expect("blocks").push(payload.status_code);
    });
    let config = SecurityConfig {
        passive_mode: true,
        ..strict_config()
    };
    let fairing = GuardFairing::from_security_config(&config)
        .expect("valid")
        .with_event_bus(bus)
        .with_on_block(hook);
    let client = client(fairing).await;
    let (status, _) = status_of(client.get("/nowhere").remote(peer(64)).dispatch().await).await;
    assert_eq!(status, Status::NotFound, "log only");
    assert_eq!(
        events.lock().expect("events").as_slice(),
        ["route_unresolved:logged_only"]
    );
    assert_eq!(blocks.lock().expect("blocks").as_slice(), [Some(500)]);
}

#[tokio::test]
async fn the_strict_route_resolution_emits_the_blocked_event_and_fires_on_block() {
    let (bus, events) = recording_bus();
    let fairing = GuardFairing::from_security_config(&strict_config())
        .expect("valid")
        .with_event_bus(bus);
    let client = client(fairing).await;
    let (status, _) = status_of(client.get("/nowhere").remote(peer(65)).dispatch().await).await;
    assert_eq!(status, Status::InternalServerError);
    assert_eq!(
        events.lock().expect("events").as_slice(),
        ["route_unresolved:request_blocked"]
    );
}

// --- request body read timeout ---

#[tokio::test]
async fn a_body_that_arrives_in_time_is_forwarded_whole() {
    let config = SecurityConfig {
        body_read_timeout: 5.0,
        ..config()
    };
    let client = client(GuardFairing::from_security_config(&config).expect("valid")).await;
    let response = client
        .post("/post")
        .remote(peer(66))
        .header(ContentType::Plain)
        .body("hello")
        .dispatch()
        .await;
    assert_eq!(status_of(response).await, (Status::Ok, "hello".to_owned()));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stalled_request_body_is_answered_408_and_never_forwarded() {
    use rocket::tokio::io::{AsyncReadExt, AsyncWriteExt};

    // The first scan of a process initializes the detection tables (seconds in a
    // debug build); warm them so the timing below measures the body read only.
    let warm = client(GuardFairing::from_security_config(&config()).expect("valid")).await;
    let (status, _) = status_of(warm.get("/hello").remote(peer(67)).dispatch().await).await;
    assert_eq!(status, Status::Ok);

    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("free port")
        .local_addr()
        .expect("addr")
        .port();
    let settings = rocket::Config {
        port,
        address: IpAddr::from([127, 0, 0, 1]),
        log_level: rocket::config::LogLevel::Off,
        ..rocket::Config::debug_default()
    };
    let config = SecurityConfig {
        body_read_timeout: 0.3,
        ..config()
    };
    let fairing = GuardFairing::from_security_config(&config).expect("valid");
    let ignited = rocket::custom(settings)
        .attach(fairing)
        .mount("/", routes![post_body])
        .ignite()
        .await
        .expect("ignite");
    let shutdown = ignited.shutdown();
    let server = rocket::tokio::spawn(ignited.launch());

    let mut stream = loop {
        match rocket::tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
            Ok(stream) => break stream,
            Err(_) => rocket::tokio::time::sleep(std::time::Duration::from_millis(20)).await,
        }
    };
    // Declare 100 bytes, send 16, then stall. (Rocket itself waits for the first
    // 14 bytes before it routes, so a stall below that never reaches the guard.)
    stream
        .write_all(
            b"POST /post HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/plain\r\nContent-Length: 100\r\nConnection: close\r\n\r\nhello, stalled!!",
        )
        .await
        .expect("write");
    let mut answer = Vec::new();
    let read = rocket::tokio::time::timeout(
        std::time::Duration::from_secs(10),
        stream.read_to_end(&mut answer),
    )
    .await;
    shutdown.notify();
    let _ = server.await;
    assert!(
        read.is_ok(),
        "the server answered before the client gave up"
    );
    let text = String::from_utf8_lossy(&answer);
    assert!(text.starts_with("HTTP/1.1 408"), "{text}");
    assert!(text.ends_with("Request body read timed out"), "{text}");
}
