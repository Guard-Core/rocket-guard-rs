//! The new public surface of the parity work: the client policy, the
//! exclusion marker, the wiring entry points (agent, dynamic rules, cloud
//! refresh, distributed stores) and the WebSocket client policy.

use guard_core_engine::behavior::BehaviorRule;
use guard_core_engine::distributed::{BanStore, SlidingWindowStore, StoreError};
use guard_core_engine::route_config::RouteConfig;
use guard_core_engine::security_config::SecurityConfig;
use guard_core_rs::composite::{TelemetryError, TelemetryHandler};
use guard_core_rs::events::SecurityEvent;
use guard_core_rs::metrics::SecurityMetric;
use rocket::get;
use rocket::http::{Header, Status};
use rocket::local::asynchronous::{Client, LocalRequest, LocalResponse};
use rocket::routes;
use rocket_guard_rs::websocket::{WebSocketGuardConfig, make_guard_websocket};
use rocket_guard_rs::{
    AgentStats, BlockGuard, ClientPolicy, Distributed, GuardConfigError, GuardExclusionScoped,
    GuardFairing, IpBanManager, PathExclusions, WebSocketGuard, Wiring, WiringOptions,
    default_config,
};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

async fn text(response: LocalResponse<'_>) -> (Status, String) {
    let status = response.status();
    (status, response.into_string().await.unwrap_or_default())
}

#[get("/<_path..>")]
#[allow(clippy::needless_pass_by_value)] // route parameters are owned by design
fn marker(
    _path: PathBuf,
    scoped: Option<GuardExclusionScoped>,
    _guard: BlockGuard,
) -> &'static str {
    if scoped.is_some() { "scoped" } else { "normal" }
}

async fn serve(fairing: GuardFairing) -> Client {
    Client::untracked(rocket::build().attach(fairing).mount("/", routes![marker]))
        .await
        .expect("valid rocket")
}

fn peer(ip: &str) -> SocketAddr {
    SocketAddr::new(ip.parse::<IpAddr>().expect("test ip"), 45_000)
}

fn get_from<'c>(client: &'c Client, ip: &str, uri: &str) -> LocalRequest<'c> {
    client.get(uri.to_owned()).remote(peer(ip))
}

#[tokio::test]
async fn an_excluded_request_carries_the_scoped_marker() {
    let fairing =
        GuardFairing::from_security_config(&SecurityConfig::default()).expect("valid config");
    let client = serve(fairing).await;
    let (_, scoped) = text(get_from(&client, "203.0.113.9", "/docs").dispatch().await).await;
    assert_eq!(scoped, "scoped");
    let (_, normal) = text(get_from(&client, "203.0.113.9", "/api").dispatch().await).await;
    assert_eq!(normal, "normal");
}

#[test]
fn the_exclusions_accessor_reports_the_normalized_matcher() {
    let fairing = GuardFairing::with_defaults()
        .with_exclude_paths(vec!["/docs/".to_owned(), "/a/../static".to_owned()]);
    assert_eq!(fairing.exclude_paths(), ["/docs", "/static"]);
    let fairing =
        GuardFairing::with_defaults().with_path_exclusions(PathExclusions::new(["/health"]));
    assert_eq!(fairing.exclude_paths(), ["/health"]);
}

#[tokio::test]
async fn a_bare_fairing_adopts_the_client_policy_it_is_given() {
    let policy = ClientPolicy {
        trusted_proxies: vec!["10.0.0.0/8".to_owned()],
        trusted_proxy_depth: 1,
        fail_secure: true,
    };
    let fairing = GuardFairing::new(default_config())
        .with_ip_gate(
            rocket_guard_rs::IpGateConfig::new([] as [&str; 0], ["203.0.113.7"], [] as [&str; 0])
                .expect("valid lists"),
        )
        .with_client_policy(policy.clone());
    assert_eq!(fairing.client_policy(), &policy);
    let client = serve(fairing).await;
    let (blocked, _) = text(
        get_from(&client, "10.0.0.1", "/api")
            .header(Header::new("x-forwarded-for", "203.0.113.7"))
            .dispatch()
            .await,
    )
    .await;
    assert_eq!(blocked, Status::Forbidden);
    let (rejected, body) = text(client.get("/api").dispatch().await).await;
    assert_eq!(rejected, Status::Forbidden);
    assert_eq!(body, "Client address could not be determined");
}

#[test]
fn an_unknown_cloud_provider_selector_fails_closed() {
    let config = SecurityConfig {
        block_cloud_providers: Some(["NotACloud".to_owned()].into_iter().collect()),
        ..SecurityConfig::default()
    };
    let error = GuardFairing::from_security_config(&config).expect_err("rejected");
    assert!(matches!(error, GuardConfigError::Cloud(_)), "{error}");
    assert!(error.to_string().contains("block_cloud_providers"));
    assert!(std::error::Error::source(&error).is_some());
}

#[test]
fn country_rules_without_a_resolver_fail_closed() {
    let config = SecurityConfig {
        blocked_countries: ["US".to_owned()].into_iter().collect(),
        ..SecurityConfig::default()
    };
    let error = GuardFairing::from_security_config(&config).expect_err("rejected");
    assert!(matches!(error, GuardConfigError::Geo(_)), "{error}");
    assert!(error.to_string().starts_with("geo:"));
    assert!(std::error::Error::source(&error).is_none());
}

#[test]
fn a_redis_error_renders_its_message() {
    let error = GuardConfigError::Redis("boom".to_owned());
    assert_eq!(error.to_string(), "redis: boom");
    assert!(std::error::Error::source(&error).is_none());
}

// --- the agent seam ---

#[derive(Default)]
struct Sink {
    events: AtomicUsize,
    metrics: AtomicUsize,
    polls: AtomicUsize,
    fail_start: bool,
}

impl TelemetryHandler for Sink {
    fn handler_name(&self) -> &'static str {
        "Sink"
    }
    fn start(&self) -> Result<(), TelemetryError> {
        if self.fail_start {
            Err(TelemetryError("start failed".to_owned()))
        } else {
            Ok(())
        }
    }
    fn stop(&self) -> Result<(), TelemetryError> {
        Ok(())
    }
    fn send_event(&self, _event: &SecurityEvent) -> Result<(), TelemetryError> {
        self.events.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn send_metric(&self, _metric: &SecurityMetric) -> Result<(), TelemetryError> {
        self.metrics.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn get_dynamic_rules(&self) -> Result<Option<serde_json::Value>, TelemetryError> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        Ok(None)
    }
    fn health_check(&self) -> bool {
        true
    }
}

fn agent_config() -> SecurityConfig {
    SecurityConfig {
        enable_agent: true,
        agent_enable_events: true,
        agent_enable_metrics: true,
        rate_limit: 1,
        ..SecurityConfig::default()
    }
}

#[test]
fn agent_stats_is_disabled_without_an_agent() {
    let fairing =
        GuardFairing::from_security_config(&SecurityConfig::default()).expect("valid config");
    assert_eq!(
        fairing.agent_stats(),
        AgentStats {
            enabled: false,
            degraded: false
        }
    );
    assert!(fairing.telemetry().is_none());
    assert!(fairing.spawn_dynamic_rules().is_none());
}

#[tokio::test]
async fn the_injected_agent_receives_the_events_and_metrics() {
    let sink = Arc::new(Sink::default());
    let fairing = GuardFairing::from_security_config_with(
        &agent_config(),
        &WiringOptions {
            agent: Some(Arc::clone(&sink) as Arc<dyn TelemetryHandler>),
            logfire_client: None,
        },
    )
    .expect("valid config");
    assert_eq!(
        fairing.agent_stats(),
        AgentStats {
            enabled: true,
            degraded: false
        }
    );
    let client = serve(fairing).await;
    let (first, _) = text(get_from(&client, "203.0.113.9", "/api").dispatch().await).await;
    assert_eq!(first, Status::Ok);
    let (second, _) = text(get_from(&client, "203.0.113.9", "/api").dispatch().await).await;
    assert_eq!(second, Status::TooManyRequests);
    assert!(
        sink.metrics.load(Ordering::SeqCst) > 0,
        "the forwarded request reached the agent as a metric"
    );
    assert!(
        sink.events.load(Ordering::SeqCst) > 0,
        "the rate-limit crossing reached the agent as an event"
    );
}

#[test]
fn a_degraded_agent_start_shows_in_the_stats() {
    let sink = Arc::new(Sink {
        fail_start: true,
        ..Sink::default()
    });
    let fairing = GuardFairing::from_security_config_with(
        &agent_config(),
        &WiringOptions {
            agent: Some(sink as Arc<dyn TelemetryHandler>),
            logfire_client: None,
        },
    )
    .expect("valid config");
    fairing.telemetry().expect("telemetry").start();
    assert_eq!(
        fairing.agent_stats(),
        AgentStats {
            enabled: true,
            degraded: true
        }
    );
}

#[test]
fn the_dynamic_rule_poll_loop_is_host_started() {
    let sink = Arc::new(Sink::default());
    let config = SecurityConfig {
        enable_dynamic_rules: true,
        dynamic_rule_interval: 1,
        ..agent_config()
    };
    let fairing = GuardFairing::from_security_config_with(
        &config,
        &WiringOptions {
            agent: Some(Arc::clone(&sink) as Arc<dyn TelemetryHandler>),
            logfire_client: None,
        },
    )
    .expect("valid config");
    assert_eq!(
        sink.polls.load(Ordering::SeqCst),
        0,
        "wiring never spawns the loop"
    );
    let handle = fairing.spawn_dynamic_rules().expect("a poll loop");
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while sink.polls.load(Ordering::SeqCst) == 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        sink.polls.load(Ordering::SeqCst) > 0,
        "the loop polled the agent"
    );
    drop(handle);
}

// --- wiring parts: cloud, distributed ---

#[tokio::test]
async fn the_cloud_stage_and_its_refresh_are_wired_from_the_config() {
    let config = SecurityConfig {
        block_cloud_providers: Some(["AWS".to_owned()].into_iter().collect()),
        ..SecurityConfig::default()
    };
    let mut wiring = Wiring::from_security_config(&config).expect("wired");
    let refresh = wiring.cloud_refresh.as_mut().expect("a refresh seam");
    refresh
        .table
        .set_provider_ranges("AWS", vec![("198.51.100.0/24".to_owned(), None)])
        .expect("ranges");
    // Keep the background refresh off the network (and from clearing the
    // ranges a failed fetch would): the scheduler has no providers.
    let scheduler =
        guard_core_rs::geo_lifecycle::CloudRefreshScheduler::new().with_providers(Vec::new());
    refresh.scheduler = Arc::new(scheduler);
    let fairing = GuardFairing::from_wiring(wiring);
    let client = serve(fairing.clone()).await;
    let (blocked, body) = text(get_from(&client, "198.51.100.5", "/api").dispatch().await).await;
    assert_eq!(blocked, Status::Forbidden);
    assert_eq!(body, "Cloud provider IP not allowed");
    let (allowed, _) = text(get_from(&client, "203.0.113.9", "/api").dispatch().await).await;
    assert_eq!(allowed, Status::Ok);
    // The global cloud rules also apply on an excluded path.
    let (scoped, scoped_body) =
        text(get_from(&client, "198.51.100.77", "/docs").dispatch().await).await;
    assert_eq!(scoped, Status::Forbidden);
    assert_eq!(scoped_body, "Cloud provider IP not allowed");
    // The maintenance call drives the same wired scheduler.
    let _scheduled = fairing.refresh_cloud_ip_ranges();
}

struct MemoryWindowStore(Mutex<HashMap<String, Vec<f64>>>);

impl SlidingWindowStore for MemoryWindowStore {
    fn record_hit(&self, key: &str, now: f64, window: u64) -> Result<u64, StoreError> {
        let mut windows = self.0.lock().expect("windows");
        let hits = windows.entry(key.to_owned()).or_default();
        hits.retain(|hit| now - hit < f64::from(u32::try_from(window).unwrap_or(u32::MAX)));
        hits.push(now);
        Ok(hits.len() as u64)
    }
}

struct MemoryBanStore(Mutex<HashMap<String, f64>>);

impl BanStore for MemoryBanStore {
    fn set_ban(&self, key: &str, expiry: f64, _ttl_seconds: u64) -> Result<(), StoreError> {
        self.0.lock().expect("bans").insert(key.to_owned(), expiry);
        Ok(())
    }
    fn get_ban(&self, key: &str) -> Result<Option<f64>, StoreError> {
        Ok(self.0.lock().expect("bans").get(key).copied())
    }
    fn delete_ban(&self, key: &str) -> Result<(), StoreError> {
        self.0.lock().expect("bans").remove(key);
        Ok(())
    }
}

#[tokio::test]
async fn the_wired_distributed_stores_carry_the_rate_limit_and_the_ban() {
    let config = SecurityConfig {
        rate_limit: 1,
        enable_rate_limit_auto_ban: true,
        auto_ban_threshold: 1,
        ..SecurityConfig::default()
    };
    let ban_store = Arc::new(MemoryBanStore(Mutex::new(HashMap::new())));
    let mut wiring = Wiring::from_security_config(&config).expect("wired");
    wiring.distributed = Some(Distributed {
        window_store: Arc::new(MemoryWindowStore(Mutex::new(HashMap::new()))),
        ban_store: Arc::clone(&ban_store) as Arc<dyn BanStore>,
        prefix: "guard_core:".to_owned(),
        fail_open: false,
    });
    let client = serve(GuardFairing::from_wiring(wiring)).await;
    let (first, _) = text(get_from(&client, "192.0.2.77", "/api").dispatch().await).await;
    assert_eq!(first, Status::Ok);
    let (second, _) = text(get_from(&client, "192.0.2.77", "/api").dispatch().await).await;
    assert_eq!(second, Status::TooManyRequests);
    assert!(
        ban_store
            .0
            .lock()
            .expect("bans")
            .contains_key("guard_core:banned_ips:192.0.2.77"),
        "the auto-ban wrote through the wired ban store"
    );
}

// --- the response body timeout ---

struct Hang;

impl rocket::tokio::io::AsyncRead for Hang {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut rocket::tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Pending
    }
}

struct Failing;

impl rocket::tokio::io::AsyncRead for Failing {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut rocket::tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Err(std::io::Error::other("stream broke")))
    }
}

/// A streamed (unsized) response body over any reader.
struct Streamed<R>(R);

impl<'r, R: rocket::tokio::io::AsyncRead + Send + 'static> rocket::response::Responder<'r, 'static>
    for Streamed<R>
{
    fn respond_to(self, _request: &'r rocket::Request<'_>) -> rocket::response::Result<'static> {
        rocket::response::Response::build()
            .streamed_body(self.0)
            .ok()
    }
}

#[get("/hang")]
fn hang(_guard: BlockGuard) -> Streamed<Hang> {
    Streamed(Hang)
}

#[get("/broken")]
fn broken(_guard: BlockGuard) -> Streamed<Failing> {
    Streamed(Failing)
}

#[get("/chunks")]
fn chunks(_guard: BlockGuard) -> Streamed<std::io::Cursor<&'static str>> {
    Streamed(std::io::Cursor::new("chunkchunk"))
}

fn secret_rule(threshold: u32, pattern: &str) -> SecurityConfig {
    SecurityConfig {
        global_behavior_rules: vec![BehaviorRule {
            rule_type: "return_pattern".to_owned(),
            threshold,
            window: 60,
            pattern: pattern.to_owned(),
            action: "ban".to_owned(),
            ban_duration: Some(60),
            correlate_with_detection: false,
        }],
        behavior_scan_response_body: true,
        ..SecurityConfig::default()
    }
}

async fn serve_streams(fairing: GuardFairing) -> Client {
    Client::untracked(
        rocket::build()
            .attach(fairing)
            .mount("/", routes![hang, broken, chunks]),
    )
    .await
    .expect("valid rocket")
}

#[tokio::test]
async fn a_stalled_response_body_times_out_fail_secure() {
    let fairing = GuardFairing::from_security_config(&secret_rule(1, "secret"))
        .expect("valid config")
        .with_body_read_timeout(Duration::from_millis(100));
    let client = serve_streams(fairing).await;
    let (status, body) = text(get_from(&client, "203.0.113.9", "/hang").dispatch().await).await;
    assert_eq!(status, Status::InternalServerError);
    assert_eq!(body, rocket_guard_rs::FAILURE_MESSAGE);
}

#[tokio::test]
async fn a_response_body_read_error_fails_secure_when_a_body_rule_needs_it() {
    let fairing = GuardFairing::from_security_config(&secret_rule(1, "secret")).expect("valid");
    let client = serve_streams(fairing).await;
    let (status, body) = text(get_from(&client, "203.0.113.9", "/broken").dispatch().await).await;
    assert_eq!(status, Status::InternalServerError);
    assert_eq!(body, rocket_guard_rs::FAILURE_MESSAGE);
}

#[tokio::test]
async fn a_streamed_response_with_a_status_only_rule_is_not_buffered() {
    // A status rule never reads the body, so a broken stream is not read by
    // the pass (it would otherwise answer the fail-secure 500).
    let fairing = GuardFairing::from_security_config(&secret_rule(5, "status:404")).expect("valid");
    let client = serve_streams(fairing).await;
    let (status, body) = text(get_from(&client, "203.0.113.9", "/chunks").dispatch().await).await;
    assert_eq!(status, Status::Ok);
    assert_eq!(body, "chunkchunk");
}

// --- the WebSocket guard resolves the client like the HTTP guard ---

#[get("/ws")]
fn ws_route(_guard: WebSocketGuard) -> &'static str {
    "ok"
}

#[tokio::test]
async fn the_websocket_guard_resolves_the_forwarded_client() {
    let manager = IpBanManager::new();
    manager
        .ban_ip("203.0.113.7".parse().expect("ip"), 600, "test ban")
        .expect("ban");
    let config = WebSocketGuardConfig::new(default_config())
        .with_ip_banning(manager)
        .with_client_policy(ClientPolicy {
            trusted_proxies: vec!["10.0.0.0/8".to_owned()],
            trusted_proxy_depth: 1,
            fail_secure: true,
        });
    let client = Client::untracked(
        rocket::build()
            .manage(make_guard_websocket(config))
            .mount("/", routes![ws_route]),
    )
    .await
    .expect("valid rocket");
    let banned = get_from(&client, "10.0.0.1", "/ws")
        .header(Header::new("x-forwarded-for", "203.0.113.7"))
        .dispatch()
        .await;
    assert_eq!(banned.status(), Status::Forbidden);
    let allowed = get_from(&client, "10.0.0.1", "/ws")
        .header(Header::new("x-forwarded-for", "198.51.100.4"))
        .dispatch()
        .await;
    assert_eq!(allowed.status(), Status::Ok);
    let unresolved = client.get("/ws").dispatch().await;
    assert_eq!(unresolved.status(), Status::Forbidden);
}

#[tokio::test]
async fn the_wiring_parts_install_one_by_one_on_a_bare_fairing() {
    let config = SecurityConfig {
        enable_dynamic_rules: true,
        block_cloud_providers: Some(["AWS".to_owned()].into_iter().collect()),
        ..agent_config()
    };
    let wiring = Wiring::from_security_config_with(
        &config,
        &WiringOptions {
            agent: Some(Arc::new(Sink::default()) as Arc<dyn TelemetryHandler>),
            logfire_client: None,
        },
    )
    .expect("wired");
    let mut refresh = wiring.cloud_refresh.clone().expect("refresh");
    refresh.scheduler = Arc::new(
        guard_core_rs::geo_lifecycle::CloudRefreshScheduler::new().with_providers(Vec::new()),
    );
    let fairing = GuardFairing::new(default_config())
        .with_telemetry(Arc::clone(wiring.telemetry.as_ref().expect("telemetry")))
        .with_dynamic_rules(wiring.dynamic_rules.clone().expect("rules"))
        .with_cloud_refresh(refresh)
        .with_auth_verifier(Arc::new(|credential| credential == "good"))
        .with_route_configs(Arc::new(|_method, _path| {
            Some(Arc::new(RouteConfig {
                auth_required: Some("bearer".to_owned()),
                ..RouteConfig::default()
            }))
        }));
    assert!(fairing.agent_stats().enabled);
    drop(fairing.spawn_dynamic_rules().expect("a loop"));
    let client = serve(fairing).await;
    let (good, _) = text(
        get_from(&client, "203.0.113.9", "/api")
            .header(Header::new("authorization", "Bearer good"))
            .dispatch()
            .await,
    )
    .await;
    assert_eq!(good, Status::Ok);
}

#[tokio::test]
async fn an_invalid_route_tier_on_an_excluded_path_fails_secure() {
    let fairing = GuardFairing::with_defaults()
        .with_exclude_paths(vec!["/docs".to_owned()])
        .with_route_configs(Arc::new(|_method, _path| {
            Some(Arc::new(RouteConfig {
                rate_limit: Some(0),
                ..RouteConfig::default()
            }))
        }));
    let client = serve(fairing).await;
    let (status, body) = text(get_from(&client, "203.0.113.9", "/docs").dispatch().await).await;
    assert_eq!(status, Status::InternalServerError);
    assert_eq!(body, rocket_guard_rs::FAILURE_MESSAGE);
}
