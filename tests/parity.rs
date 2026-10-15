//! Reference-parity behavior of the public API: the scoped `exclude_paths`
//! semantics, client resolution, the `from_security_config` consumption, and
//! the response pass. Every test drives a real Rocket application through the
//! public surface only.

use guard_core_engine::behavior::BehaviorRule;
use guard_core_engine::geo::GeoIpHandler;
use guard_core_engine::route_config::RouteConfig;
use guard_core_engine::security_config::SecurityConfig;
use rocket::get;
use rocket::http::{Header, Status};
use rocket::local::asynchronous::{Client, LocalRequest, LocalResponse};
use rocket::routes;
use rocket_guard_rs::{BlockGuard, GuardFairing, IpBanConfig, IpBanManager, default_config};
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

const ATTACK_QUERY: &str = "q=%3Cscript%3Ealert(1)%3C/script%3E";

struct Out {
    status: Status,
    body: String,
    headers: Vec<(String, String)>,
}

async fn out(response: LocalResponse<'_>) -> Out {
    let status = response.status();
    let headers = response
        .headers()
        .iter()
        .map(|header| {
            (
                header.name().as_str().to_lowercase(),
                header.value().to_owned(),
            )
        })
        .collect();
    let body = response.into_string().await.unwrap_or_default();
    Out {
        status,
        body,
        headers,
    }
}

fn header(out: &Out, name: &str) -> Option<String> {
    out.headers
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.clone())
}

#[get("/<_path..>")]
#[allow(clippy::needless_pass_by_value)] // route parameters are owned by design
fn catch_all(_path: PathBuf, _guard: BlockGuard) -> &'static str {
    "ok"
}

#[get("/<_path..>", rank = 1)]
#[allow(clippy::needless_pass_by_value)] // route parameters are owned by design
fn secret_body(_path: PathBuf, _guard: BlockGuard) -> &'static str {
    "the secret token is 42"
}

async fn serve(fairing: GuardFairing) -> Client {
    Client::untracked(
        rocket::build()
            .attach(fairing)
            .mount("/", routes![catch_all]),
    )
    .await
    .expect("valid rocket")
}

async fn serve_secret(fairing: GuardFairing) -> Client {
    Client::untracked(
        rocket::build()
            .attach(fairing)
            .mount("/", routes![secret_body]),
    )
    .await
    .expect("valid rocket")
}

fn peer(ip: &str) -> SocketAddr {
    SocketAddr::new(ip.parse::<IpAddr>().expect("test ip"), 45_000)
}

fn get_from<'c>(client: &'c Client, ip: &str, uri: &str) -> LocalRequest<'c> {
    client.get(uri.to_owned()).remote(peer(ip))
}

fn from_config(config: &SecurityConfig) -> GuardFairing {
    GuardFairing::from_security_config(config).expect("valid config")
}

struct FixedCountry(&'static str);

impl GeoIpHandler for FixedCountry {
    fn get_country(&self, _ip: IpAddr) -> Option<String> {
        Some(self.0.to_owned())
    }
}

fn return_rule(pattern: &str, threshold: u32) -> BehaviorRule {
    BehaviorRule {
        rule_type: "return_pattern".to_owned(),
        threshold,
        window: 60,
        pattern: pattern.to_owned(),
        action: "ban".to_owned(),
        ban_duration: Some(60),
        correlate_with_detection: false,
    }
}

// --- exclude_paths: the reference matcher, scoped not bypassed ---

#[tokio::test]
async fn the_default_static_exclusion_covers_nested_assets_on_a_segment_boundary() {
    let client = serve(from_config(&SecurityConfig::default())).await;
    let nested = out(get_from(
        &client,
        "203.0.113.9",
        &format!("/static/app.js?{ATTACK_QUERY}"),
    )
    .dispatch()
    .await)
    .await;
    assert_eq!(nested.status, Status::Ok, "/static covers /static/app.js");
    let sibling = out(get_from(
        &client,
        "203.0.113.9",
        &format!("/staticx/app.js?{ATTACK_QUERY}"),
    )
    .dispatch()
    .await)
    .await;
    assert_eq!(
        sibling.status,
        Status::BadRequest,
        "/staticx is not under /static"
    );
}

#[tokio::test]
async fn an_encoded_traversal_out_of_an_excluded_prefix_is_not_excluded() {
    let client = serve(from_config(&SecurityConfig::default())).await;
    let escaped = out(get_from(
        &client,
        "203.0.113.9",
        &format!("/static/%2e%2e/private?{ATTACK_QUERY}"),
    )
    .dispatch()
    .await)
    .await;
    assert_eq!(escaped.status, Status::BadRequest);
}

#[tokio::test]
async fn an_excluded_path_still_answers_a_live_ban() {
    let manager = IpBanManager::new();
    manager
        .ban_ip("203.0.113.9".parse().expect("ip"), 600, "test ban")
        .expect("ban");
    let fairing = GuardFairing::with_defaults()
        .with_exclude_paths(vec!["/docs".to_owned()])
        .with_ip_banning(
            manager,
            IpBanConfig::new(
                true,
                5,
                3600,
                Vec::<(String, rocket_guard_rs::ThreatBanEntry)>::new(),
            )
            .expect("valid config"),
        );
    let client = serve(fairing).await;
    let banned = out(get_from(&client, "203.0.113.9", "/docs").dispatch().await).await;
    assert_eq!(banned.status, Status::Forbidden);
    assert_eq!(banned.body, rocket_guard_rs::BANNED_MESSAGE);
    let other = out(get_from(&client, "203.0.113.10", "/docs").dispatch().await).await;
    assert_eq!(other.status, Status::Ok);
}

#[tokio::test]
async fn an_excluded_path_still_enforces_the_global_ip_lists() {
    let config = SecurityConfig {
        blacklist: vec!["203.0.113.9".to_owned()],
        ..SecurityConfig::default()
    };
    let client = serve(from_config(&config)).await;
    let blocked = out(get_from(&client, "203.0.113.9", "/docs").dispatch().await).await;
    assert_eq!(blocked.status, Status::Forbidden);
    assert_eq!(blocked.body, rocket_guard_rs::FORBIDDEN_MESSAGE);
    let allowed = out(get_from(&client, "203.0.113.10", "/docs").dispatch().await).await;
    assert_eq!(allowed.status, Status::Ok);
}

#[tokio::test]
async fn an_excluded_path_still_hits_the_rate_limit() {
    let config = SecurityConfig {
        rate_limit: 2,
        ..SecurityConfig::default()
    };
    let client = serve(from_config(&config)).await;
    for _ in 0..2 {
        let passed = out(get_from(&client, "203.0.113.9", "/docs").dispatch().await).await;
        assert_eq!(passed.status, Status::Ok);
    }
    let limited = out(get_from(&client, "203.0.113.9", "/docs").dispatch().await).await;
    assert_eq!(limited.status, Status::TooManyRequests);
    assert_eq!(header(&limited, "retry-after").as_deref(), Some("60"));
}

#[tokio::test]
async fn an_excluded_path_still_applies_the_global_country_rules() {
    let config = SecurityConfig {
        blocked_countries: ["US".to_owned()].into_iter().collect(),
        geo_ip_handler: Some(Arc::new(FixedCountry("US"))),
        ..SecurityConfig::default()
    };
    let client = serve(from_config(&config)).await;
    let blocked = out(get_from(&client, "203.0.113.9", "/docs").dispatch().await).await;
    assert_eq!(blocked.status, Status::Forbidden);
}

#[tokio::test]
async fn an_excluded_path_ignores_the_route_ip_restrictions() {
    let fairing = GuardFairing::with_defaults()
        .with_exclude_paths(vec!["/docs".to_owned()])
        .with_route_configs(Arc::new(|_method, _path| {
            Some(Arc::new(RouteConfig {
                ip_blacklist: Some(vec!["203.0.113.9".to_owned()]),
                ..RouteConfig::default()
            }))
        }));
    let client = serve(fairing).await;
    let excluded = out(get_from(&client, "203.0.113.9", "/docs").dispatch().await).await;
    assert_eq!(excluded.status, Status::Ok, "route lists do not apply");
    let guarded = out(get_from(&client, "203.0.113.9", "/api").dispatch().await).await;
    assert_eq!(guarded.status, Status::Forbidden);
}

#[tokio::test]
async fn an_excluded_path_skips_https_enforcement() {
    let config = SecurityConfig {
        enforce_https: true,
        ..SecurityConfig::default()
    };
    let client = serve(from_config(&config)).await;
    let excluded = out(get_from(&client, "203.0.113.9", "/docs").dispatch().await).await;
    assert_eq!(excluded.status, Status::Ok);
    let other = out(get_from(&client, "203.0.113.9", "/api").dispatch().await).await;
    assert_eq!(other.status, Status::MovedPermanently);
}

#[tokio::test]
async fn an_excluded_response_still_gets_the_security_headers() {
    let client = serve(from_config(&SecurityConfig::default())).await;
    let excluded = out(get_from(&client, "203.0.113.9", "/docs").dispatch().await).await;
    assert_eq!(excluded.status, Status::Ok);
    assert_eq!(
        header(&excluded, "x-content-type-options").as_deref(),
        Some("nosniff")
    );
}

fn recording_collector() -> (rocket_guard_rs::MetricsCollector, Arc<Mutex<Vec<String>>>) {
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    let collector = guard_core_rs::metrics::MetricsCollector::new(true).with_handler(Arc::new(
        move |metric: &guard_core_rs::metrics::SecurityMetric| {
            sink.lock().expect("sink").push(metric.metric_type.clone());
        },
    ));
    (collector, seen)
}

#[tokio::test]
async fn an_excluded_response_emits_the_request_metrics() {
    let (collector, seen) = recording_collector();
    let client = serve(from_config(&SecurityConfig::default()).with_metrics(collector)).await;
    let excluded = out(get_from(&client, "203.0.113.9", "/docs").dispatch().await).await;
    assert_eq!(excluded.status, Status::Ok);
    let recorded = seen.lock().expect("sink").clone();
    assert!(
        recorded.iter().any(|kind| kind == "request_count"),
        "the excluded request is counted: {recorded:?}"
    );
}

#[tokio::test]
async fn an_excluded_request_does_not_feed_the_return_rules() {
    // A rule trips once its count exceeds the threshold (2): the third
    // tracked response trips it and the fourth request is banned.
    let config = SecurityConfig {
        global_behavior_rules: vec![return_rule("status:200", 2)],
        ..SecurityConfig::default()
    };
    let client = serve(from_config(&config)).await;
    // The excluded request is withheld from the behavioral tracker: were it
    // counted, the rule would trip one request earlier.
    let excluded = out(get_from(&client, "203.0.113.9", "/docs").dispatch().await).await;
    assert_eq!(excluded.status, Status::Ok);
    for _ in 0..3 {
        let tracked = out(get_from(&client, "203.0.113.9", "/api").dispatch().await).await;
        assert_eq!(
            tracked.status,
            Status::Ok,
            "the excluded hit did not count toward the rule"
        );
    }
    let banned = out(get_from(&client, "203.0.113.9", "/api").dispatch().await).await;
    assert_eq!(banned.status, Status::Forbidden);
}

// --- client resolution ---

#[tokio::test]
async fn a_missing_client_address_is_rejected_under_fail_secure() {
    let client = serve(from_config(&SecurityConfig::default())).await;
    let rejected = out(client.get("/api").dispatch().await).await;
    assert_eq!(rejected.status, Status::Forbidden);
    assert_eq!(rejected.body, "Client address could not be determined");
    assert_eq!(
        header(&rejected, "x-content-type-options").as_deref(),
        Some("nosniff"),
        "the rejection rides the response pass"
    );
}

#[tokio::test]
async fn the_unresolved_client_rejection_fires_the_block_hook() {
    let seen: Arc<Mutex<Vec<guard_core_engine::payload::BlockPayload>>> =
        Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    let config = SecurityConfig {
        on_block: Some(Arc::new(move |payload| {
            sink.lock().expect("sink").push(payload.clone());
        })),
        ..SecurityConfig::default()
    };
    let client = serve(from_config(&config)).await;
    let rejected = out(client.get("/api").dispatch().await).await;
    assert_eq!(rejected.status, Status::Forbidden);
    let payloads = seen.lock().expect("sink").clone();
    assert_eq!(payloads.len(), 1);
    assert_eq!(payloads[0].check_name, "client_address_unresolved");
    assert_eq!(payloads[0].reason, "Client address could not be determined");
    assert_eq!(payloads[0].status_code, Some(403));
}

#[tokio::test]
async fn a_missing_client_address_continues_unattributed_without_fail_secure() {
    let config = SecurityConfig {
        fail_secure: false,
        ..SecurityConfig::default()
    };
    let client = serve(from_config(&config)).await;
    let passed = out(client.get("/api").dispatch().await).await;
    assert_eq!(passed.status, Status::Ok);
}

#[tokio::test]
async fn a_bare_fairing_without_a_peer_keeps_passing() {
    let client = serve(GuardFairing::new(default_config())).await;
    let passed = out(client.get("/api").dispatch().await).await;
    assert_eq!(passed.status, Status::Ok);
}

#[tokio::test]
async fn an_excluded_path_without_a_peer_continues_scoped() {
    let client = serve(from_config(&SecurityConfig::default())).await;
    let excluded = out(client.get("/static/app.js").dispatch().await).await;
    assert_eq!(excluded.status, Status::Ok);
    let rejected = out(client.get("/api").dispatch().await).await;
    assert_eq!(rejected.status, Status::Forbidden);
}

fn behind_a_proxy() -> SecurityConfig {
    SecurityConfig {
        trusted_proxies: vec!["10.0.0.0/8".to_owned()],
        blacklist: vec!["203.0.113.7".to_owned()],
        ..SecurityConfig::default()
    }
}

#[tokio::test]
async fn a_trusted_proxy_forwards_the_real_client_identity() {
    let client = serve(from_config(&behind_a_proxy())).await;
    let blocked = out(get_from(&client, "10.0.0.1", "/api")
        .header(Header::new("x-forwarded-for", "203.0.113.7"))
        .dispatch()
        .await)
    .await;
    assert_eq!(
        blocked.status,
        Status::Forbidden,
        "the forwarded client is the identity the gate sees"
    );
    let allowed = out(get_from(&client, "10.0.0.1", "/api")
        .header(Header::new("x-forwarded-for", "198.51.100.4"))
        .dispatch()
        .await)
    .await;
    assert_eq!(allowed.status, Status::Ok);
}

#[tokio::test]
async fn an_untrusted_peer_cannot_spoof_the_forwarded_identity() {
    let config = SecurityConfig {
        blacklist: vec!["203.0.113.9".to_owned()],
        ..behind_a_proxy()
    };
    let client = serve(from_config(&config)).await;
    // The peer is not a trusted proxy: its own address is the identity,
    // whatever X-Forwarded-For claims.
    let spoofed = out(get_from(&client, "203.0.113.9", "/api")
        .header(Header::new("x-forwarded-for", "198.51.100.4"))
        .dispatch()
        .await)
    .await;
    assert_eq!(spoofed.status, Status::Forbidden);
    let innocent = out(get_from(&client, "198.51.100.99", "/api")
        .header(Header::new("x-forwarded-for", "203.0.113.7"))
        .dispatch()
        .await)
    .await;
    assert_eq!(innocent.status, Status::Ok);
}

#[tokio::test]
async fn a_spoofed_x_real_ip_header_does_not_change_the_identity() {
    // Rocket's own `client_ip()` honors `X-Real-IP` unconditionally; the
    // guard resolves from the connecting peer and the trusted proxies only.
    let config = SecurityConfig {
        blacklist: vec!["203.0.113.9".to_owned()],
        ..SecurityConfig::default()
    };
    let client = serve(from_config(&config)).await;
    let spoofed = out(get_from(&client, "203.0.113.9", "/api")
        .header(Header::new("x-real-ip", "198.51.100.4"))
        .dispatch()
        .await)
    .await;
    assert_eq!(spoofed.status, Status::Forbidden);
}

#[tokio::test]
async fn the_rate_limit_keys_on_the_forwarded_client_not_the_proxy() {
    let config = SecurityConfig {
        trusted_proxies: vec!["10.0.0.0/8".to_owned()],
        rate_limit: 1,
        ..SecurityConfig::default()
    };
    let client = serve(from_config(&config)).await;
    let first = out(get_from(&client, "10.0.0.1", "/api")
        .header(Header::new("x-forwarded-for", "198.51.100.4"))
        .dispatch()
        .await)
    .await;
    assert_eq!(first.status, Status::Ok);
    let other_client = out(get_from(&client, "10.0.0.1", "/api")
        .header(Header::new("x-forwarded-for", "198.51.100.5"))
        .dispatch()
        .await)
    .await;
    assert_eq!(
        other_client.status,
        Status::Ok,
        "a different forwarded client has its own window"
    );
    let same_client = out(get_from(&client, "10.0.0.1", "/api")
        .header(Header::new("x-forwarded-for", "198.51.100.4"))
        .dispatch()
        .await)
    .await;
    assert_eq!(same_client.status, Status::TooManyRequests);
}

#[tokio::test]
async fn an_ipv4_mapped_peer_matches_the_v4_list_entry() {
    let config = SecurityConfig {
        blacklist: vec!["203.0.113.9".to_owned()],
        ..SecurityConfig::default()
    };
    let client = serve(from_config(&config)).await;
    let blocked = out(client
        .get("/api")
        .remote("[::ffff:203.0.113.9]:45000".parse().expect("addr"))
        .dispatch()
        .await)
    .await;
    assert_eq!(blocked.status, Status::Forbidden);
}

#[tokio::test]
async fn a_forged_forwarded_proto_from_an_untrusted_peer_is_still_redirected() {
    let config = SecurityConfig {
        enforce_https: true,
        trust_x_forwarded_proto: true,
        trusted_proxies: vec!["10.0.0.0/8".to_owned()],
        ..SecurityConfig::default()
    };
    let client = serve(from_config(&config)).await;
    let forged = out(get_from(&client, "198.51.100.4", "/api")
        .header(Header::new("x-forwarded-proto", "https"))
        .dispatch()
        .await)
    .await;
    assert_eq!(forged.status, Status::MovedPermanently);
    let trusted = out(get_from(&client, "10.0.0.1", "/api")
        .header(Header::new("x-forwarded-proto", "https"))
        .dispatch()
        .await)
    .await;
    assert_eq!(trusted.status, Status::Ok);
}

#[tokio::test]
async fn a_whitelisted_ip_is_exempt_from_the_user_agent_block() {
    let config = SecurityConfig {
        whitelist: Some(vec!["203.0.113.9".to_owned()]),
        blocked_user_agents: vec!["badbot".to_owned()],
        ..SecurityConfig::default()
    };
    let client = serve(from_config(&config)).await;
    let whitelisted = out(get_from(&client, "203.0.113.9", "/api")
        .header(Header::new("user-agent", "badbot/1.0"))
        .dispatch()
        .await)
    .await;
    assert_eq!(whitelisted.status, Status::Ok);
}

// --- from_security_config: every stage reachable ---

#[tokio::test]
async fn the_country_rules_reach_the_geo_stage() {
    let config = SecurityConfig {
        blocked_countries: ["US".to_owned()].into_iter().collect(),
        geo_ip_handler: Some(Arc::new(FixedCountry("US"))),
        ..SecurityConfig::default()
    };
    let client = serve(from_config(&config)).await;
    let blocked = out(get_from(&client, "203.0.113.9", "/api").dispatch().await).await;
    assert_eq!(blocked.status, Status::Forbidden);
    let other = SecurityConfig {
        blocked_countries: ["US".to_owned()].into_iter().collect(),
        geo_ip_handler: Some(Arc::new(FixedCountry("DE"))),
        ..SecurityConfig::default()
    };
    let client = serve(from_config(&other)).await;
    let allowed = out(get_from(&client, "203.0.113.9", "/api").dispatch().await).await;
    assert_eq!(allowed.status, Status::Ok);
}

#[tokio::test]
async fn the_endpoint_rate_limits_reach_the_limiter() {
    let mut endpoint_rate_limits = BTreeMap::new();
    endpoint_rate_limits.insert("/login".to_owned(), (1_u32, 60_u64));
    let config = SecurityConfig {
        endpoint_rate_limits,
        ..SecurityConfig::default()
    };
    let client = serve(from_config(&config)).await;
    let first = out(get_from(&client, "203.0.113.9", "/login").dispatch().await).await;
    assert_eq!(first.status, Status::Ok);
    let second = out(get_from(&client, "203.0.113.9", "/login").dispatch().await).await;
    assert_eq!(second.status, Status::TooManyRequests);
    let elsewhere = out(get_from(&client, "203.0.113.9", "/other").dispatch().await).await;
    assert_eq!(elsewhere.status, Status::Ok);
}

#[tokio::test]
async fn the_rate_limit_auto_ban_reaches_the_limiter() {
    let config = SecurityConfig {
        rate_limit: 1,
        enable_rate_limit_auto_ban: true,
        auto_ban_threshold: 1,
        ..SecurityConfig::default()
    };
    let client = serve(from_config(&config)).await;
    let first = out(get_from(&client, "203.0.113.9", "/api").dispatch().await).await;
    assert_eq!(first.status, Status::Ok);
    let crossing = out(get_from(&client, "203.0.113.9", "/api").dispatch().await).await;
    assert_eq!(crossing.status, Status::TooManyRequests);
    let banned = out(get_from(&client, "203.0.113.9", "/api").dispatch().await).await;
    assert_eq!(banned.status, Status::Forbidden);
    assert_eq!(banned.body, rocket_guard_rs::BANNED_MESSAGE);
}

#[tokio::test]
async fn the_custom_request_check_reaches_the_pipeline() {
    let config = SecurityConfig {
        custom_request_check: Some(Arc::new(|ctx| {
            (ctx.path == "/teapot").then_some(guard_core_engine::custom_checks::CustomResponse {
                status: Some(418),
                body: None,
            })
        })),
        ..SecurityConfig::default()
    };
    let client = serve(from_config(&config)).await;
    let blocked = out(get_from(&client, "203.0.113.9", "/teapot").dispatch().await).await;
    assert_eq!(blocked.status.code, 418);
    let passed = out(get_from(&client, "203.0.113.9", "/api").dispatch().await).await;
    assert_eq!(passed.status, Status::Ok);
}

#[tokio::test]
async fn the_global_auth_verifier_backs_the_route_authentication() {
    let config = SecurityConfig {
        auth_verifier: Some(Arc::new(|credential| credential == "good")),
        ..SecurityConfig::default()
    };
    let fairing = from_config(&config).with_route_configs(Arc::new(|_method, _path| {
        Some(Arc::new(RouteConfig {
            auth_required: Some("bearer".to_owned()),
            ..RouteConfig::default()
        }))
    }));
    let client = serve(fairing).await;
    let good = out(get_from(&client, "203.0.113.9", "/api")
        .header(Header::new("authorization", "Bearer good"))
        .dispatch()
        .await)
    .await;
    assert_eq!(good.status, Status::Ok);
    let bad = out(get_from(&client, "203.0.113.9", "/api")
        .header(Header::new("authorization", "Bearer nope"))
        .dispatch()
        .await)
    .await;
    assert_eq!(bad.status, Status::Unauthorized);
}

#[tokio::test]
async fn the_cors_expose_headers_reach_the_response() {
    let config = SecurityConfig {
        enable_cors: true,
        cors_allow_origins: vec!["https://app.example.com".to_owned()],
        cors_expose_headers: vec!["X-Trace".to_owned()],
        ..SecurityConfig::default()
    };
    let client = serve(from_config(&config)).await;
    let answered = out(get_from(&client, "203.0.113.9", "/api")
        .header(Header::new("origin", "https://app.example.com"))
        .dispatch()
        .await)
    .await;
    assert_eq!(answered.status, Status::Ok);
    assert_eq!(
        header(&answered, "access-control-expose-headers").as_deref(),
        Some("X-Trace")
    );
    assert_eq!(header(&answered, "vary").as_deref(), Some("Origin"));
}

#[tokio::test]
async fn the_config_modifier_runs_once_and_the_config_error_hook_reports() {
    let calls = Arc::new(Mutex::new(0_u32));
    let counter = Arc::clone(&calls);
    let config = SecurityConfig {
        custom_response_modifier: Some(Arc::new(move |bits| {
            *counter.lock().expect("counter") += 1;
            bits.headers
                .insert("x-modified".to_owned(), "yes".to_owned());
        })),
        ..SecurityConfig::default()
    };
    let client = serve(from_config(&config)).await;
    let answered = out(get_from(&client, "203.0.113.9", "/api").dispatch().await).await;
    assert_eq!(header(&answered, "x-modified").as_deref(), Some("yes"));
    assert_eq!(*calls.lock().expect("counter"), 1, "applied exactly once");

    let reported: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&reported);
    let panicking = SecurityConfig {
        custom_response_modifier: Some(Arc::new(|_bits| panic!("modifier exploded"))),
        on_error: Some(Arc::new(move |stage, _error, _context| {
            sink.lock().expect("sink").push(stage.to_owned());
        })),
        ..SecurityConfig::default()
    };
    let client = serve(from_config(&panicking)).await;
    let survived = out(get_from(&client, "203.0.113.9", "/api").dispatch().await).await;
    assert_eq!(survived.status, Status::Ok);
    assert_eq!(
        reported.lock().expect("sink").as_slice(),
        ["custom_response_modifier"]
    );
}

#[tokio::test]
async fn a_return_rule_ban_is_enforced_by_the_ban_stage() {
    let config = SecurityConfig {
        global_behavior_rules: vec![return_rule("status:200", 0)],
        ..SecurityConfig::default()
    };
    let client = serve(from_config(&config)).await;
    let first = out(get_from(&client, "203.0.113.9", "/api").dispatch().await).await;
    assert_eq!(first.status, Status::Ok);
    let banned = out(get_from(&client, "203.0.113.9", "/api").dispatch().await).await;
    assert_eq!(banned.status, Status::Forbidden);
}

// --- the response pass ---

#[tokio::test]
async fn the_modifier_runs_without_a_response_processor() {
    let fairing =
        GuardFairing::new(default_config()).with_custom_response_modifier(Arc::new(|bits| {
            bits.headers
                .insert("x-modified".to_owned(), "yes".to_owned());
        }));
    let client = serve(fairing).await;
    let answered = out(get_from(&client, "203.0.113.9", "/api").dispatch().await).await;
    assert_eq!(answered.status, Status::Ok);
    assert_eq!(header(&answered, "x-modified").as_deref(), Some("yes"));
}

#[tokio::test]
async fn a_return_rule_matches_the_response_body_and_the_body_is_re_emitted() {
    let config = SecurityConfig {
        global_behavior_rules: vec![return_rule("secret", 0)],
        behavior_scan_response_body: true,
        ..SecurityConfig::default()
    };
    let client = serve_secret(from_config(&config)).await;
    let first = out(get_from(&client, "203.0.113.9", "/api").dispatch().await).await;
    assert_eq!(first.status, Status::Ok);
    assert_eq!(
        first.body, "the secret token is 42",
        "the full body survives"
    );
    let banned = out(get_from(&client, "203.0.113.9", "/api").dispatch().await).await;
    assert_eq!(banned.status, Status::Forbidden);
}

#[tokio::test]
async fn a_body_rule_does_not_match_a_clean_body() {
    let config = SecurityConfig {
        global_behavior_rules: vec![return_rule("secret", 0)],
        behavior_scan_response_body: true,
        ..SecurityConfig::default()
    };
    let client = serve(from_config(&config)).await;
    for _ in 0..3 {
        let passed = out(get_from(&client, "203.0.113.9", "/api").dispatch().await).await;
        assert_eq!(passed.status, Status::Ok);
        assert_eq!(passed.body, "ok");
    }
}

// --- all-checks-bypass routes ---

fn all_bypass_routes() -> rocket_guard_rs::RouteConfigResolver {
    Arc::new(|_method, path| {
        (path == "/open").then(|| {
            Arc::new(RouteConfig {
                bypassed_checks: ["all".to_owned()].into_iter().collect(),
                ..RouteConfig::default()
            })
        })
    })
}

fn recording_bus() -> (
    Arc<guard_core_rs::events::SecurityEventBus>,
    Arc<Mutex<Vec<guard_core_rs::events::SecurityEvent>>>,
) {
    let seen: Arc<Mutex<Vec<guard_core_rs::events::SecurityEvent>>> =
        Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    let bus = guard_core_rs::events::SecurityEventBus::new(true).on_event(Arc::new(
        move |event: &guard_core_rs::events::SecurityEvent| {
            sink.lock().expect("sink").push(event.clone());
        },
    ));
    (Arc::new(bus), seen)
}

#[tokio::test]
async fn an_all_bypass_route_skips_the_pipeline_emits_the_event_and_runs_only_the_modifier() {
    let (bus, seen) = recording_bus();
    let (collector, metrics_seen) = recording_collector();
    let config = SecurityConfig {
        custom_response_modifier: Some(Arc::new(|bits| {
            bits.headers
                .insert("x-modified".to_owned(), "yes".to_owned());
        })),
        ..SecurityConfig::default()
    };
    let fairing = from_config(&config)
        .with_route_configs(all_bypass_routes())
        .with_event_bus(bus)
        .with_metrics(collector);
    let client = serve(fairing).await;
    let bypassed = out(
        get_from(&client, "203.0.113.9", &format!("/open?{ATTACK_QUERY}"))
            .dispatch()
            .await,
    )
    .await;
    assert_eq!(bypassed.status, Status::Ok, "the attack is not scanned");
    assert_eq!(header(&bypassed, "x-modified").as_deref(), Some("yes"));
    assert_eq!(
        header(&bypassed, "x-content-type-options"),
        None,
        "no security headers on a fully bypassed route"
    );
    assert!(
        metrics_seen.lock().expect("sink").is_empty(),
        "no metrics on a fully bypassed route"
    );
    let events = seen.lock().expect("sink").clone();
    let bypass = events
        .iter()
        .find(|event| event.event_type == "security_bypass")
        .expect("the security_bypass event fired");
    assert_eq!(bypass.action_taken, "all_checks_bypassed");
    assert_eq!(
        bypass.reason,
        "Route configured to bypass all security checks"
    );
    let checked = out(
        get_from(&client, "203.0.113.9", &format!("/guarded?{ATTACK_QUERY}"))
            .dispatch()
            .await,
    )
    .await;
    assert_eq!(checked.status, Status::BadRequest);
}

#[tokio::test]
async fn an_all_bypass_route_continues_through_the_pipeline_in_passive_mode() {
    let (bus, seen) = recording_bus();
    let config = SecurityConfig {
        passive_mode: true,
        ..SecurityConfig::default()
    };
    let fairing = from_config(&config)
        .with_route_configs(all_bypass_routes())
        .with_event_bus(bus);
    let client = serve(fairing).await;
    let passive = out(get_from(&client, "203.0.113.9", "/open").dispatch().await).await;
    assert_eq!(passive.status, Status::Ok);
    assert_eq!(
        header(&passive, "x-content-type-options").as_deref(),
        Some("nosniff"),
        "passive mode keeps the response pass"
    );
    assert!(
        seen.lock()
            .expect("sink")
            .iter()
            .any(|event| event.event_type == "security_bypass"),
        "the event still fires under passive mode"
    );
}

#[tokio::test]
async fn an_all_bypass_route_without_an_event_bus_still_forwards() {
    let fairing = GuardFairing::with_defaults().with_route_configs(all_bypass_routes());
    let client = serve(fairing).await;
    let bypassed = out(
        get_from(&client, "203.0.113.9", &format!("/open?{ATTACK_QUERY}"))
            .dispatch()
            .await,
    )
    .await;
    assert_eq!(bypassed.status, Status::Ok);
}
