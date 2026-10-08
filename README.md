# rocket-guard-rs

Application-layer security middleware for [Rocket](https://rocket.rs) 0.5, powered by the [guard-core-rs](https://github.com/Guard-Core/guard-core-rs) detection engine. Part of the [guard ecosystem](https://github.com/Guard-Core).

Docs: <https://guard-core.github.io/rocket-guard-rs/>

**Status:** Released. Version 1.2.0, published to crates.io. `GuardFairing`, `BlockGuard`, and `GuardBody` are working Rocket integration, screened by the engine.

## About

The guard ecosystem provides application-layer API security middleware across multiple languages and frameworks:

- **Python**: [fastapi-guard](https://github.com/Guard-Core/fastapi-guard), [flaskapi-guard](https://github.com/Guard-Core/flaskapi-guard), [djapi-guard](https://github.com/Guard-Core/djapi-guard), [tornadoapi-guard](https://github.com/Guard-Core/tornadoapi-guard)
- **TypeScript**: guard-core-ts with adapters for Express, Fastify, Hono, NestJS
- **Rust**: [guard-core-rs](https://github.com/Guard-Core/guard-core-rs) with adapters for [tower](https://github.com/Guard-Core/tower-guard-rs), [axum](https://github.com/Guard-Core/axum-guard-rs), [actix-web](https://github.com/Guard-Core/actix-guard-rs), [rocket](https://github.com/Guard-Core/rocket-guard-rs) (this repo)

Per the ecosystem boundary rules, this crate holds framework glue only: every detection decision comes from the engine.

## Wiring: two steps, because Rocket needs two

Rocket has no middleware chain that can abort a request: a fairing's `on_request` cannot short-circuit, and Rocket's own source calls request guards "the correct mechanism" for refusal. The adapter splits the work accordingly:

1. **Attach the fairing.** `GuardFairing` scans the path, query, and header views of every request in `on_request` and stashes the verdict in request-local state; it also registers the `400`/`403`/`413`/`429`/`500` catchers that render refusals (skipping statuses the application already registered, since Rocket treats same-code catchers at the same base as a fatal collision).
2. **Add a guard argument to each protected route.** `BlockGuard` for routes without a body, `GuardBody` for routes with one. This is the part Rocket cannot automate: protection is per-route by design.

```rust
use rocket::{get, post, routes};
use rocket_guard_rs::{BlockGuard, GuardBody, GuardFairing, default_config};

#[get("/health")]
fn health(_guard: BlockGuard) -> &'static str {
    "ok"
}

#[post("/submit", data = "<body>")]
fn submit(body: GuardBody) -> Vec<u8> {
    body.into_inner()
}

#[rocket::launch]
fn rocket() -> _ {
    rocket::build()
        .attach(GuardFairing::new(default_config()))
        .mount("/", routes![health, submit])
}
```

Routes without either guard argument are scanned but not blocked. The fairing additionally rewrites a `404` to the guarded refusal shape when the verdict is a block, so a threat to a path that matches no route does not leak a `404`; a `404` is proof that no handler ran, which is why that rewrite is safe.

The full crate documentation is in [`src/lib.rs`](src/lib.rs) (build it with `cargo doc --open`).

## What it inspects

One engine call per request view, mirroring the mapping used by the sibling adapters:

| Request part | Engine context | Notes |
|---|---|---|
| Path | `url_path` | Skipped for `/` |
| Query string | `query_param` | Skipped when empty |
| Header values | `header` | Skips `sec-*` and the negotiation/routing headers (`Host`, `User-Agent`, `Accept`, `Accept-Encoding`, `Connection`, `Origin`, `Referer`) |
| Body | `request_body` | Buffered by `GuardBody`, capped (see below) |

The HTTP method is not fed to the engine: the engine's `detect(content, context, config)` takes content plus a context, and the reference adapters do not scan the method either.

## Engine surfaces (public config)

Every stateful decision and emission runs through the engine facade's rate-limit stage, configured through `GuardFairing` builders:

| Surface | Builder / idiom |
|---|---|
| Rate-limit tiers | `.with_route_tiers(resolver)` (`path -> Option<RouteRateLimits>`), `.with_geo_handler(handler)` (geo tiers); per-request override via `set_route_rate_limits(&request, tiers)` |
| Detection exclusions | `.with_detection_exclusions(config)` (global `excluded_detection_headers/params/body_fields`, `enabled_detection_categories`, `detection_scan_body`), `.with_route_detection_exclusions(resolver)` (per route), or the `set_route_detection_exclusions(&request, exclusions)` request-local setter |
| Events + log settings | `.with_event_bus(bus)` (`SecurityEventBus` hook registration), `.with_observability(config)` (`log_suspicious_level`, `muted_check_logs`, the `log_sensitive_headers/params/body_fields` redaction sets) |
| `on_block` + custom errors | `.with_on_block(hook)`, `.with_custom_error_responses(map)` (status-to-body overrides on every block answer, including the `400` detection block, honored by the catchers and the `404` rewrite) |
| Distributed mode | `.with_distributed_store(window_store, prefix, fail_open)` + `.with_distributed_ban_store(ban_store)` (fail-closed backend errors answer `503 Redis rate limiting unavailable`) |
| Passive mode | `.with_passive_mode(true)` (windows and counters still record, log lines and events still fire, no block renders, auto-ban feeds suppressed) |

Two-phase note (framework shape, reference-matching order): Rocket's `on_request` never sees the request body, so the fairing runs the full stage pass (bans, rate-limit tiers, the metadata finding) in `on_request` - recording the request's single rate-window hit there - and the body finding feeds later through the stage's split `feed_finding` seam, exactly how the reference pipeline orders rate limiting before body processing.

## Responses

| Situation | Status | Body |
|---|---|---|
| The IP gate denies the client IP | `403 Forbidden` | `Forbidden` |
| A live ban on the client IP | `403 Forbidden` | `IP address banned` |
| Rate limit crossed | `429 Too Many Requests` (+ `Retry-After: <window>`) | `Too many requests` |
| Engine flags a view | `400 Bad Request` | `Suspicious activity detected` |
| Engine flags a view and a crossed auto-ban threshold bans on the spot | `403 Forbidden` | `IP has been banned` |
| Body exceeds the cap | `413 Payload Too Large` | `Payload too large` |
| Body read error or engine panic | `500 Internal Server Error` | `Security check failed` |

The bodies follow the ecosystem's plain-text error convention (the bare message, `text/plain; charset=utf-8`, same as the Python family), but the adapter is deliberately **fail-secure**: unlike the TypeScript adapters, whose check pipeline logs and skips on error, any failure to complete the security check answers `500`, never an uninspected passthrough. A guard with no stashed verdict (fairing not attached) also refuses with `500`.

Engine panics are caught with `catch_unwind`, so a detected panic still produces a response instead of unwinding out of the request. `panic = "abort"` in the release profile disables that recovery.

## Rate limiting and IP banning

Two opt-in builder methods install the engine's stateful stage, mirroring the reference pipeline's order (ban check first, then the limiter, both in `on_request` before the metadata scan and the guards):

```rust
use rocket_guard_rs::{GuardFairing, IpBanConfig, IpBanManager, RateLimitConfig, RateLimiter, ThreatBanEntry};

let limiter = RateLimiter::new(RateLimitConfig {
    enable_rate_limiting: true,
    rate_limit: 30,
    rate_limit_window: 10,
    ..RateLimitConfig::default()
})
.expect("valid config");

let manager = IpBanManager::new();
let bans = IpBanConfig::new(
    true,
    10,
    3600,
    [("sqli", ThreatBanEntry { threshold: 3, duration: 1800 })],
)
.expect("valid config");

let fairing = rocket_guard_rs::GuardFairing::with_defaults()
    .with_rate_limiting(limiter)
    .with_ip_banning(manager, bans);
```

- A rate-limit crossing answers `429 Too Many Requests` with `Retry-After: <window seconds>`. With the limiter's `enable_rate_limit_auto_ban` on, every crossing counts one `rate_limit` violation toward the auto-ban engine; the response stays `429` and the ban bites on the next request (`403 IP address banned`).
- A live ban on the client IP answers `403 Forbidden` (`IP address banned`) before the limiter, so banned traffic never consumes rate budget.
- Every detected threat counts its categories per client IP; a crossed `threat_ban_config` entry (or the flat `auto_ban_threshold`) bans on the spot, answering `403 Forbidden` (`IP has been banned`). `config.enable_ip_banning = false` counts violations but never bans.
- Both stages honor the `exempt_ips` contract: whitelisted and exempt IPs are never rate limited, never banned, and never counted; unattributed requests (no client IP) skip the stage but are still detection-screened.
- The limiter and the ban store pair are shared with the managed engine state, and the engine handles are cheaply clonable, so out-of-band handles (admin unban endpoints, stats) work alongside the installed fairing.

## Body cap

Rocket streams request bodies to data guards, and a fairing can only peek at the first 512 bytes (`Data::peek` is capped at `PEEK_BYTES`). Scanning a truncated prefix as if it were the body would be a bypass vector, so the body view is scanned by `GuardBody`, which owns the data stream.

Bodies are buffered up to the cap configured on the fairing, defaulting to the engine's full-scan cap (`DetectConfig::max_full_scan_bytes`, 262 144 bytes in the ecosystem default):

```rust
let fairing = rocket_guard_rs::GuardFairing::with_defaults()
    .with_body_cap(1_048_576);
```

A body larger than the cap is rejected with `413` rather than forwarded unscanned. Rocket's own `limits` continue to apply inside handlers; a limit violation raised by Rocket's guards (for example `Json`) is also a `413` error outcome and therefore also gets the plain-text `Payload too large` body.

## Status route

`status::GuardStatus` in managed state plus the `status::guard_status` route handler is the `add_status_route` mirror (fastapi-guard `guard/status.py` + `HandlerInitializer.get_initialization_status`): `.manage(GuardStatus::new().with_cloud_table(table)).mount(status::DEFAULT_STATUS_PATH, routes![guard_status])` mounts `GET /_guard/status`, serving the cloud-provider status table (`{"ready":..., "last_refreshed":<unix-seconds|null>, "entries":N}` per provider from the live `CloudIpTable`) and the geo-ip component (`null` without a handler, `{"configured":true}` with the lookup trait only, the `{ready, last_refreshed, entries}` health snapshot with the `IpInfoManager` lifecycle manager). The maintenance trio lives on `GuardFairing`: `reset()` drops the rate-limit windows, `refresh_cloud_ip_ranges()` schedules one single-flight refresh through `with_cloud_refresh_scheduler`, and `agent_stats()` answers the reference property's no-agent shape.

## WebSocket guard (rocket_ws)

Rocket 0.5's WebSocket surface is the official [`rocket_ws`](https://crates.io/crates/rocket_ws) crate, and `websocket::WebSocketGuard` guards it, ported from fastapi-guard's `guard/websocket.py` (`make_guard_websocket`): install the guard with `.manage(make_guard_websocket(config))` and declare it on the `rocket_ws` routes it protects. A blocked handshake is rejected with `403 Forbidden` pre-accept, carrying the close shape on `x-guard-websocket-close` / `x-guard-websocket-close-reason` (Starlette's `WebSocketException` denial, translated like the axum/actix siblings). The close codes are the reference's: `1008 Policy Violation` for every policy denial (IP banned, IP not allowed, rate limit exceeded, unknown client address under fail-secure, suspicious activity) and `1013 Try Again Later` for an engine malfunction (a panic in the check sequence, contained). The sequence: fail-secure unknown address, the ban arm, the `is_ip_allowed` gate + country arms (a whitelist match skips countries), the `ws` rate limit (skipped for whitelisted IPs), then the path/query/header penetration scan - an upgrade carries no body.

Frames after the upgrade are guarded too: `WebSocketGuard::scan_frame(client_ip, &message)` scans one text or binary message through the engine, feeds the shared violation store on a threat, and reports the close shape the channel answers with (`WebSocketGuard::close_frame` + `stream_error`); control frames pass untouched. `WebSocketGuardConfig::with_violation_feed(ViolationFeed::new(counters, ban_config))` installs the shared-suspicious-counts store (the reference's shared `suspicious_request_counts`): a crossed threshold bans the address through the shared `IpBanManager`, and the next handshake's ban arm then rejects it - frame threats close the current connection with the suspicious-activity close exactly like the reference's single detection arm. Build the config from the handles the app already holds with `WebSocketGuardConfig::new(default_config())` + the `with_ip_gate` / `with_ip_banning` / `with_rate_limiting` / `with_country_rules` / `with_violation_feed` / `with_fail_secure` builders. The fairing itself passes upgrades through like any request; the guard is the per-route surface Rocket's model requires.

## Engine dependency

The Cargo.toml pins `guard-core-engine` and `guard-core-rs` at 4.2.0 and carries paths pointing at the engine and facade crates inside a sibling `guard-core-rs` checkout so local builds and CI compile them from source. Registry note, stated plainly: the 4.1.0 dists were yanked (the version-accuracy fix for the family tag mistake), so 1.1.0 could not resolve its engine from the registry alone; the synchronized 4.2.0 train restores resolution (`rocket-guard-rs` 1.2.0 over `guard-core-engine`/`guard-core-rs` 4.2.0). CI checks out `Guard-Core/guard-core-rs` (see [`.github/workflows/ci.yml`](.github/workflows/ci.yml)), mirroring the sibling adapter pattern in `tower-guard-rs` and `actix-guard-rs`.

Both halves of the sibling checkout are used: `guard-core-engine` for the detection entry point and the engine-side stages, and the `guard-core-rs` facade for the stage layers (the `guard_core_rs::*` stage types the fairing installs).

## Stage surface (the reference 17-check pipeline, wired)

Every reference check the engine ships is installable on `GuardFairing`, and the fairing runs the installed set in the reference pipeline order: emergency mode, HTTPS enforcement, request logging, request size/content caps, required headers + authentication, referrer, custom validators, time windows, geo country blocking, cloud-provider blocking, user-agent filtering, bans, rate limiting, the custom-request check, and the response-side pass (behavioral return rules + security headers + CORS). The builder table lives in the crate docs, including the Rocket-specific seams (the ban arm before geo/cloud/user-agent, the tiers after, the HTTPS redirect rendered in `on_response` because Rocket catchers are `400`-`599` only).

## Not wired on purpose

- **WebSocket guard (fairing half)**: the fairing scans an upgrade's path, query, and header views like any request, but the handshake rejection and the per-frame guard live in the `websocket::WebSocketGuard` route surface, not the fairing; a `rocket_ws` route without the guard argument is not WS-guarded.

## Development

- MSRV: 1.92 (matches guard-core-rs); edition 2024
- Requires a sibling `guard-core-rs` checkout at `../guard-core-rs`

```bash
cargo check --all-targets
cargo test
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
```

CI (`.github/workflows/ci.yml`) runs the same checks on stable plus an MSRV 1.92 job, checking out `guard-core-rs` first so the path dependency resolves.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
