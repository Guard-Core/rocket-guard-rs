//! Production-shaped guarded Rocket application.
//!
//! Differences from `simple_app`:
//!
//! - The engine [`DetectConfig`] and the adapter body cap are driven by
//!   environment variables (see `env_config` below), so a deployment tunes
//!   detection without a rebuild.
//! - The per-route enforcement split is made explicit: guarded routes
//!   (`BlockGuard` / `GuardBody`) refuse threats, `/health` is excluded
//!   (no guard argument), and `/open` is scanned but deliberately not
//!   blocked, demonstrating that in Rocket protection is per-route opt-in.
//! - A threat to a path that matches no route is answered with the guarded
//!   `400` (the fairing rewrites the `404`), so probe traffic never leaks
//!   route inventory.
//!
//! Note on route-scoped guard configuration: Rocket fairings are global, and
//! the adapter stores one verdict per request, so attaching a second fairing
//! with a stricter config cannot scope it to a route subtree. The adapter
//! surface has no route IDs; see the tower/axum/actix examples for the
//! route-scoped configuration demo. The guard-core-rs engine currently ships
//! the CPU-bound detection pipeline only: there is no rate limiter, ban
//! manager, or Redis surface to drive.

use rocket::get;
use rocket::post;
use rocket::routes;
use rocket_guard_rs::{BlockGuard, GuardBody, GuardFairing, default_config};

#[get("/health")]
fn health() -> &'static str {
    "ok"
}

#[get("/")]
fn root(_guard: BlockGuard) -> &'static str {
    "rocket-guard-rs advanced app"
}

#[get("/search?<q>")]
fn search(_guard: BlockGuard, q: &str) -> String {
    format!("search ok: {q}")
}

#[post("/echo", data = "<body>")]
fn echo(_guard: BlockGuard, body: GuardBody) -> Vec<u8> {
    body.into_inner()
}

/// Scanned by the fairing but never blocked: no guard argument. A threat on
/// this route reaches the handler; that is the per-route opt-in story.
#[get("/open")]
fn open() -> &'static str {
    "open route, no guard"
}

/// Guarded exactly like the public routes; the strict-config variant lives in
/// the tower/axum/actix advanced examples, which can scope guard configs.
#[get("/admin/stats")]
fn admin_stats(_guard: BlockGuard) -> &'static str {
    "stats"
}

/// Build the engine [`DetectConfig`] from environment variables.
///
/// Every knob is optional; unset variables fall back to the ecosystem
/// defaults pinned in [`default_config`].
///
/// | Variable | Field | Default |
/// |---|---|---|
/// | `GUARD_MAX_CONTENT_LENGTH` | `max_content_length` | `10000` |
/// | `GUARD_MAX_FULL_SCAN_BYTES` | `max_full_scan_bytes` | `262144` |
/// | `GUARD_PRESERVE_ATTACK_PATTERNS` | `preserve_attack_patterns` | `true` |
/// | `GUARD_SEMANTIC_THRESHOLD` | `semantic_threshold` | `0.7` |
/// | `GUARD_THREAT_SCORE_THRESHOLD` | `threat_score_threshold` | `1.0` |
/// | `GUARD_BINARY_MIN_RUN_LENGTH` | `binary_min_run_length` | `16` |
/// | `GUARD_MAX_SCAN_VALUES` | `max_scan_values` | `512` |
/// | `GUARD_MAX_SCAN_CHARS` | `max_scan_chars` | `65536` |
/// | `GUARD_MAX_JSON_DEPTH` | `max_json_depth` | `32` |
fn env_config() -> rocket_guard_rs::DetectConfig {
    let defaults = default_config();
    rocket_guard_rs::DetectConfig {
        max_content_length: env_usize("GUARD_MAX_CONTENT_LENGTH", defaults.max_content_length),
        max_full_scan_bytes: env_usize("GUARD_MAX_FULL_SCAN_BYTES", defaults.max_full_scan_bytes),
        preserve_attack_patterns: env_bool(
            "GUARD_PRESERVE_ATTACK_PATTERNS",
            defaults.preserve_attack_patterns,
        ),
        semantic_threshold: env_f64("GUARD_SEMANTIC_THRESHOLD", defaults.semantic_threshold),
        threat_score_threshold: env_f64(
            "GUARD_THREAT_SCORE_THRESHOLD",
            defaults.threat_score_threshold,
        ),
        binary_min_run_length: env_usize(
            "GUARD_BINARY_MIN_RUN_LENGTH",
            defaults.binary_min_run_length,
        ),
        max_scan_values: env_usize("GUARD_MAX_SCAN_VALUES", defaults.max_scan_values),
        max_scan_chars: env_usize("GUARD_MAX_SCAN_CHARS", defaults.max_scan_chars),
        max_json_depth: env_usize("GUARD_MAX_JSON_DEPTH", defaults.max_json_depth),
    }
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn env_f64(name: &str, default: f64) -> f64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn env_bool(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(value) => matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes"),
        Err(_) => default,
    }
}

#[rocket::launch]
fn rocket() -> _ {
    let config = env_config();
    let body_cap = env_usize("GUARD_BODY_CAP", config.max_full_scan_bytes);

    rocket::build()
        .attach(GuardFairing::new(config).with_body_cap(body_cap))
        .mount("/", routes![health, root, search, echo, open, admin_stats])
}
