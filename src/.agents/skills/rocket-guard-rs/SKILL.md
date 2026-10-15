---
name: rocket-guard-rs
description: Use when working in rocket-guard-rs (github.com/Guard-Core/rocket-guard-rs), the Rocket Fairing adapter for the guard-core-rs detection engine: editing the fairing, guards, WebSocket guard or status route, wiring guard-core-rs into a Rocket application, or answering questions about what the crate does. It is implemented, tested and published; the engine is a path dependency into a sibling guard-core-rs checkout.
---

# rocket-guard-rs

The Rocket adapter of the Guard ecosystem. `GuardFairing` screens Rocket 0.5 traffic through the guard-core-rs engine, and the request guards `BlockGuard` and `GuardBody` enforce the verdict per route. It holds framework glue only; every detection decision comes from the engine.

## Quick Reference

- Status: implemented, tested, published to crates.io. Edition 2024, MSRV 1.92, MIT OR Apache-2.0.
- Engine: [guard-core-rs](https://github.com/Guard-Core/guard-core-rs), consumed as a path dependency into a sibling checkout at `../guard-core-rs` (the facade supplies the stages and the `Wiring`).
- Entry points: `GuardFairing::new` / `with_defaults` (builder API) and `GuardFairing::from_security_config` / `from_security_config_with` (the whole `SecurityConfig` through the facade's `Wiring`).

## Installation

```bash
cargo add rocket-guard-rs
```

To work on the source, clone the repo next to a `guard-core-rs` checkout:

```bash
git clone https://github.com/Guard-Core/rocket-guard-rs
git clone https://github.com/Guard-Core/guard-core-rs
cd rocket-guard-rs
```

## How it works

Rocket has no middleware chain that can abort a request, so the work is split in two:

1. `GuardFairing` (`Kind::Ignite | Kind::Request | Kind::Response`): `on_ignite` manages the engine and registers the `400`/`403`/`413`/`429`/`500` catchers (never over an application-claimed status), `on_request` resolves the client, runs the pipeline and stashes the verdict in request-local state, `on_response` renders the `301` HTTPS redirect, rewrites a `404` to the guarded refusal, emits the metrics and runs the response pass.
2. `BlockGuard` (routes without a body) and `GuardBody` (routes with one) enforce the stashed verdict before the handler runs. A route without a guard argument is scanned but never blocked, and a guard that finds no verdict refuses with `500` (fail-secure).

Pipeline order inside `on_request` follows the reference: client resolution, the CORS preflight short-circuit, the exclusion decision, route resolution, the all-checks-bypass route, then (for a normal request) usage rules, route IP and country rules, the global IP gate, emergency mode, HTTPS, request logging, headers and auth, referrer, validators, time window, the metadata scan, bans, geo, cloud, user agent, the rate-limit tiers and `custom_request`. The body view is scanned later, in `GuardBody`.

## Config surface

- `from_security_config(&config)` builds everything through `guard_core_rs::wiring::Wiring` (the field table is in that module's docs): geo country rules, cloud providers with the per-request refresh, `endpoint_rate_limits`, the rate-limit auto-ban, `custom_request_check`, `auth_verifier` (fallback of a route's verifiers), the response modifier and `on_error`, `cors_expose_headers`, trusted proxies, the telemetry sink and event bus, dynamic rules.
- `from_security_config_with(&config, &WiringOptions { agent, logfire_client })` injects the telemetry agent through the facade's `TelemetryHandler` (build one from the `agent_*` fields with guard-agent-rs's `GuardAgentTelemetry`). Wiring starts nothing: the host calls `telemetry().start()` and `spawn_dynamic_rules()`.
- Client policy: `with_client_policy(ClientPolicy)`. The identity is the connecting peer plus `X-Forwarded-For` through trusted proxies; Rocket's `client_ip()` (which trusts `X-Real-IP`) is never used. A bare fairing defaults to `fail_secure = false`, `from_security_config` installs the config's (`true` by default, a peer-less request answers `403 Client address could not be determined`).
- `exclude_paths` uses the engine matcher and is scoped, not bypassed: bans, the global IP rules and the rate limit still apply, the request carries `GuardExclusionScoped`, and the response gets metrics, headers, CORS and the modifier. A route that bypasses `all` emits `security_bypass` and gets only the modifier.
- Not applied: `route_resolution_strict` (Rocket resolves routes after `on_request`), the request-body read timeout (Rocket's limits own it), the `redis` backend (enable the facade's `redis` feature yourself).

## Other surfaces

- `status::GuardStatus` and `status::guard_status`: the `GET /_guard/status` route (managed state plus a mounted handler).
- `websocket::WebSocketGuard` and `make_guard_websocket`: the `rocket_ws` handshake guard and the per-frame `scan_frame`, with the same client policy through `WebSocketGuardConfig::with_client_policy`.

## Development Commands

```bash
cargo check --all-targets
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo build -p guard-core-engine --bins   # builds the pattern-probe child the scan tests need
cargo test
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
cargo llvm-cov --lcov --output-path lcov.info && python3 .github/scripts/enforce_line_coverage.py lcov.info   # 100% lines
```

`make test` and `make lint` wrap the same commands over the workspace (the adapter plus `examples/`).

## Footguns

- **Do not add security logic here**: detection belongs in guard-core-rs; this crate is glue only.
- **Every refusal is a verdict**: a fairing cannot answer from `on_request`, so new blocks must stash a verdict and let the guards, catchers or the `404` rewrite render it. Do not invent another mechanism.
- **Never use `Request::client_ip()`**: it honors the `X-Real-IP` header from any peer. Use the resolved client from `scan::client_ip`.
- **Rocket's Shield adds `X-Content-Type-Options`**: assert the guard's security headers through a header only the guard sets (for example `Referrer-Policy`).
- **Fail-secure stays**: any new failure path maps to `500` or a documented rejection, never an uninspected passthrough.
- **CI enforces 100% line coverage**: every new line needs a test, no waivers.

## Related Projects

- [guard-core-rs](https://github.com/Guard-Core/guard-core-rs): the engine.
- Sibling adapters: [tower-guard-rs](https://github.com/Guard-Core/tower-guard-rs), [axum-guard-rs](https://github.com/Guard-Core/axum-guard-rs), [actix-guard-rs](https://github.com/Guard-Core/actix-guard-rs).
- [guard-core](https://github.com/Guard-Core/guard-core): Python reference implementation and spec owner.
- [fastapi-guard](https://github.com/Guard-Core/fastapi-guard): the most mature adapter, the reference for feature coverage.
