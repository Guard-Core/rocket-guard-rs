# Changelog

All notable changes to this project.

v1.4.0 (2026-10-07)
-------------------

The reference-surface release: the status route lands in managed state, training with the 4.3.1 parity-completion engine (v1.4.0)
---------------------------------------------------------------------------------------------------------------------------------

### Note

- Trains with the engine: the `guard-core-engine` and `guard-core-rs` floors move to 4.3.1 (the parity-completion release)

### Added

- The reference status route (fastapi-guard `add_status_route` + `HandlerInitializer.get_initialization_status`): `GuardStatus` in managed state plus the `guard_status` route handler mounted at `/_guard/status`, serving the cloud-provider readiness table and the geo-ip component from the handles the app already holds (#38). The WebSocket upgrade guard has no surface here: rocket has no stable 0.5 WS surface to guard

## [Unreleased]

### Added

- The WebSocket guard for Rocket's official `rocket_ws` surface (fastapi-guard `guard/websocket.py`'s `make_guard_websocket`, the GAP-A9 rocket leg): `.manage(make_guard_websocket(WebSocketGuardConfig))` + the `WebSocketGuard` request guard on `rocket_ws` routes runs the reference check sequence before the handshake completes - fail-secure unknown address, the ban arm, the `is_ip_allowed` gate + country arms (a whitelist match skips countries), the `ws` rate limit (skipped for whitelisted IPs), then the path/query/header penetration scan - and a blocked handshake answers `403 Forbidden` pre-accept with the close shape on `x-guard-websocket-close` / `x-guard-websocket-close-reason` (`1008 Policy Violation` policy denials, `1013 Try Again Later` malfunctions, the panic in the check sequence contained). The guard also covers frames after the upgrade: `WebSocketGuard::scan_frame` scans one text/binary message through the engine (control frames pass), answers the reference close shape (`close_frame` + `stream_error`), and feeds the shared violation store installed by `with_violation_feed` (the reference's shared `suspicious_request_counts`): a crossed threshold bans the address through the shared `IpBanManager`, and the next handshake's ban arm rejects it; `rocket_ws` rides in as a dependency

- The reference route-config carrier consumption (`GuardFairing::with_route_configs` + `set_route_config`, the GAP-R2 rocket leg): the engine's `RouteConfigResolver` (`(method, path) -> Option<Arc<RouteConfig>>`) resolves the route's `RouteConfig` once per `on_request` pass - a carrier stashed with `set_route_config` wins over the resolver (the reference `request.state.route_config` idiom) - and the pipeline consumes it with the reference semantics: `bypassed_checks` (and the `"all"` wildcard) skip the named reference checks at their pipeline positions (the fused stages map as documented: `required_headers`/`authentication` skip the headers-auth stage, `ip_security` skips the gate, ban, and geo arms, `suspicious_activity` skips the scan and its violation feed, `rate_limit` skips the whole tiers pass), `require_https` rides the HTTPS stage's carrier lane (`decide_route`; with no stage installed the route arm still composes the reference `301`), `max_request_size` replaces the body cap the data guard enforces, `blocked_user_agents` runs additively before the global filter through the trusted-compile lane (a non-compilable route pattern fails secure `500`), the rate-limit group becomes the route's tier (an invalid tier fails secure), and the detection-exclusion group resolves through the engine's detection view; `RouteConfig`/`RouteConfigResolver` re-exported


### Added

- The unified-config consumption (`GuardFairing::from_security_config`, the GAP-R1 rocket leg): the 129-field `SecurityConfig` (the fieldized reference surface in guard-core-engine) builds the wired pipeline in one call - the detection budgets onto `DetectConfig`, the IP lists onto the gate, the rate-limit knobs onto the limiter, the ban group onto `IpBanManager` + `IpBanConfig`, `enforce_https`/`trust_x_forwarded_proto` onto the HTTPS stage, `emergency_mode` + its whitelist onto the emergency stage, `custom_error_responses`/`on_block` onto the response surface, the detection-exclusion group (with the reference's empty-set-disables-all-categories semantics) onto the scan, the observability group onto the log/redaction knobs, ReDoS-validated `blocked_user_agents`, and the security-headers/CORS/behavior response pass; invalid values fail closed through the new typed `GuardConfigError`; the reference `exclude_paths` carve-out lands as a first-class builder consumed first in the pipeline (an excluded path bypasses every request-side check, gate included, the response pass still renders); `SecurityConfig`, `SecurityConfigError`, `GuardConfigError`, and the `LogLevel`/`LogFormat`/`BufferOverflowPolicy` knob enums re-exported

### Changed
- The bypass consumption now uses the reference's coarse query vocabulary (the ip gate, the route IP restrictions, and the country arms query `ip`; the ban arm `ip_ban`; the cloud-provider check `clouds`; the rate limiter `rate_limit`; the penetration scan `penetration`; the `"all"` wildcard matches every query) - the previous wave keyed the bypass on the 17 stage names, a vocabulary the reference never queries (the stages it named are not route-bypassable in the reference at all, and their bypass conditions are removed); the `require_https` carrier lane falls back to the HTTPS stage's own resolver seam when no carrier route applies, and the custom-checks seam carries the body slot the engine's validator contract defines (`decide_custom_request`/`decide_custom_validators` take the body; the fairing's `on_request` phase never sees one - Rocket's data guard owns the stream - so it passes `None`, the two-phase flow's documented divergence)

- The IP-gate denial path now renders the reference ip_filter behavior end to end: passive mode logs the crossing and forwards (no verdict stashed, no gate decision downstream), the `on_block` hook fires once with the reference payload keys (`ip_security`), and the custom-error body override wins over the family default - previously the gate denial rendered the family body unconditionally and skipped both

- The CI coverage gate computes line coverage from the lcov export's per-line DA records instead of llvm-cov's summary table: llvm-cov 22's summary aggregation falsely reports missed lines that no line-level view (show text/html, lcov, cobertura, the JSON segment list) can see on the same profdata, and the divergence persists on the newest available toolchain (cargo-llvm-cov 0.9.1 + rustc 1.99.0). The gate keeps the same fail-closed 100%-lines semantics with nothing hidden or excluded; the summary table stays in the job as an informational printout. Evidence linked in the workflow (#37)

## [1.3.0] - 2026-10-01

### Note

- Trains with the engine: the `guard-core-engine` and `guard-core-rs` floors move to 4.3.0 (the safety-chain release). The adapter ships no logic changes of its own

### Changed

- Process and CI chores: the community and security process scaffold (#23), the 100% line coverage gate enforced with cargo-llvm-cov (#24), the CDLA-Permissive-2.0 license allowed from the engine sibling's graph (#30), and the routine GitHub Actions dependency bumps (#25-#29, #31-#33)

## [1.2.0] - 2026-09-27

### Note

- Trains with the engine: `guard-core-engine` and `guard-core-rs` floors move to 4.2.0 (the 4.1.0 engine dists were yanked; this release restores registry resolution)

### Added

- The wave surfaces are publicly configurable on `GuardFairing`, each wired to the engine facade's rate-limit stage (`guard_core_rs::tower::RateLimitStage`, built in `on_ignite` and carried in the managed engine state; every stateful decision and emission goes through it):
  - `with_route_tiers(resolver)` (`path -> Option<RouteRateLimits>`) and `with_geo_handler(Arc<dyn GeoIpHandler>)`: the reference's endpoint/route/geo rate-limit tiers; the first tier that crosses answers the same `429 + Retry-After` shape and feeds the auto-ban engine; the request-local `set_route_rate_limits(&request, tiers)` setter covers the per-route decorator idiom
  - `with_detection_exclusions(DetectionExclusionConfig)` + `with_route_detection_exclusions(resolver)` (+ the `set_route_detection_exclusions` setter): the reference per-route detection-exclusion surface, resolved per request through the engine's `detection_exclusions::resolve` + `scan_request`
  - `with_event_bus(Arc<SecurityEventBus>)`: the `penetration_attempt`/`rate_limited`/`ip_banned` events with the reference fields, metadata, and redaction
  - `with_observability(ObservabilityConfig)`: `log_suspicious_level`, `muted_check_logs`, and the `log_sensitive_headers/params/body_fields` redaction sets
  - `with_on_block(OnBlockHook)` and `with_custom_error_responses(CustomErrorResponses)`: the hook fires exactly once per blocked request (and per passive-flagged detection with no status); the status-to-body map overrides every block body, honored by the catchers and the `404` rewrite
  - `with_distributed_store(window_store, redis_prefix, redis_fail_open)` + `with_distributed_ban_store(store)`: the reference distributed mode (fail-closed backend errors answer the new `503 "Redis rate limiting unavailable"` shape, `fail_open = true` degrades to the in-memory window)
  - `with_passive_mode(bool)`: the reference passive mode - windows and counters record, log lines and events fire, no block ever renders
- New re-exports: `DetectionExclusionConfig`, `RouteDetectionExclusions`, `GeoIpHandler`, `BanStore`, `SlidingWindowStore`, `ViolationCounters`, `RouteRateLimits`, `RateLimitEntry`, `RateLimitTier`, `TierDecision`, `SecurityEventBus`, `ObservabilityConfig`, `RequestObservation`, `StageResponse`, `BlockPayload`, `OnBlockHook`, `CustomErrorResponses`, and the `set_route_rate_limits`/`set_route_detection_exclusions` setters

### Changed

- `guard-core-rs` (the engine facade) joins `guard-core-engine` as a pinned 4.1.0 dependency with the sibling-checkout path fallback; the stage delegation keeps the existing `with_rate_limiting`/`with_ip_banning` shared-handle semantics (out-of-band bans and custom clocks honored) through the stage builder's `limiter`/`ban_manager` injection seams
- Two-phase flow (documented framework mismatch, reference-matching order): Rocket's `on_request` never sees the body, so the fairing runs bans + rate-limit tiers + the metadata finding there (the request's single rate-window hit records at `on_request`), and the `GuardBody` data guard feeds the body finding through the engine stage's split `feed_finding` seam - no window double-recording, and rate limiting still precedes body processing exactly as the reference pipeline orders it
- Scan semantics move onto the engine's reference surface: the query string is scanned as `parse_qsl`-decoded per-parameter pairs (previously one raw encoded blob), and the headers the exclusion resolution marks are scanned with their known false-positive categories suppressed (`ssrf` for address-chain values) instead of an adapter-level blanket skip. Exempt IPs now feed the violation counters (the reference suspicious-activity stage skips a whitelisted IP only; detection still scans and blocks them), so a crossed threshold bans even an exempt attacker


### Added

- Stateful stage (rate limiting, dynamic bans, auto-ban) over the engine's `rate_limit` and `ip_ban` modules, mirroring the tower reference implementation:
  - `GuardFairing::with_rate_limiting(RateLimiter)`: the sliding-window limiter runs in `on_request` after the IP gate and the ban check, before the metadata scan - a crossing answers `429 Too Many Requests` with `Retry-After: <window seconds>`, the references' rate-limit shape. With the limiter's `enable_rate_limit_auto_ban` on, every crossing counts one `rate_limit` violation toward the auto-ban engine (`threat_ban_config["rate_limit"]` first, then the flat threshold), the reference pipeline's `_record_rate_limit_autoban`
  - `GuardFairing::with_ip_banning(IpBanManager, IpBanConfig)`: a live ban answers `403 Forbidden` (`IP address banned`) before the limiter, so banned traffic never consumes rate budget; every detected threat counts its categories per client IP (the reference pipeline's suspicious-activity stage) and a crossed `threat_ban_config` entry or the flat `auto_ban_threshold` bans on the spot, answering `403 Forbidden` (`IP has been banned`); `config.enable_ip_banning = false` counts violations but never bans; the plain detection block keeps the reference suspicious-activity stage's `400 Bad Request` (`Suspicious activity detected`) shape
  - both stages honor the `exempt_ips` contract: whitelisted and exempt IPs are never rate limited, never banned (ban stage), and never have violations counted - which makes `exempt_ips` observable under load; unattributed requests (no client IP) cannot be held responsible and skip the stage, detection still screens them
  - the limiter and the ban store pair are shared with the managed engine state, and `RateLimiter`, `IpBanManager`, and `ViolationCounters` are cheaply clonable and clone-share their stores, so out-of-band handles (admin unban endpoints, stats) work alongside the installed fairing

### Changed

- Detection blocks answer `400 Bad Request` (`Suspicious activity detected`) instead of `403 Forbidden`, matching the reference suspicious-activity stage's status and the rest of the Rust family (the IP gate's `403 Forbidden` and the fail-secure `500` are unchanged); the registered catchers and the fairing's unrouted-path `404` rewrite carry the family's five-shape contract

## [1.1.0] - 2026-09-26

### Added

- Optional global IP gate (`GuardFairing::with_ip_gate` over the new engine `IpGateConfig`): `whitelist`, `blacklist`, and `exempt_ips` lists parsed once at startup (invalid entry is a config error, fail closed), evaluated in `on_request` before the metadata scan on the request's client IP - a blacklisted client IP, or one a non-empty `whitelist` matches neither directly nor through `exempt_ips`, is refused with `403 Forbidden`, including the unrouted-path `404` rewrite so probe traffic never reveals route inventory. `exempt_ips` is the skip-list for known-friendly automation: it sets the same skip state a whitelist match sets but never adds a deny path and never opens the whitelist gate; the blacklist and detection still apply to exempt IPs. Requests without a client IP (Rocket's local test client) are not attributed and still screened by detection

### Changed

- `guard-core-engine` dependency pinned to the published 4.1.0 release (path dep kept for local builds and CI against a sibling `guard-core-rs` checkout), carrying the stateful sliding-window rate limiter and dynamic IP ban engine, the tower stage with a reusable `decide()`, and the new detection stages (request size/content, user-agent, headers/auth, cloud provider blocking, geo blocking)
- The request body is no longer scanned as one lossy blob: it is routed by content type through the engine's body-value extraction (guard-core 4.0.4 parity, upstream commit 5f399234), and every extracted value is scanned through the normal detect path with its reference context - urlencoded field values under `request_body:form_field`, multipart part entries (label scan, `filename="..."` entry with RFC 2231 handling, raw part headers, payload) under `request_body:multipart_field`, embedded JSON leaves under the `:embedded_json` suffix, JSON mongo operator keys (`$where`, `$ne`, ...) as direct `nosql` hits, and the whole-body blob only as the fallback for plain or unparseable bodies
- Binary-dense multipart file-part payloads are reduced to printable runs of at least `detection_binary_min_run_length` (default 16) before pattern scanning, so compressed upload bytes stop producing attack-shaped matches while text embedded in uploads still scans in full; text uploads, text parts without a filename, and whole-body fallback scans keep their full scan
- 403/413/500 short-circuit responses now carry the bare message (`Suspicious activity detected`, `Payload too large`, `Security check failed`) as `text/plain; charset=utf-8`, matching the Python family's block-response convention, instead of the JSON `{"detail":"..."}` shape

## [1.0.0] - 2026-09-24

### Added

- First stable release of `rocket-guard-rs` 1.0.0: application-layer security Fairing for Rocket 0.5, powered by `guard-core-engine` 4.0.4 (17/17 checks parity with guard-core 4.0.4, binary-noise gates)
- Guard Fairing: one engine call per request view (path, query string, headers, buffered body), 403/413/500 fail-secure responses with the ecosystem JSON `detail` shape, configurable body cap (default: engine full-scan cap), `catch_unwind` panic recovery
- Example apps: `examples/simple_app` and `examples/advanced_app` with Dockerfiles and docker-compose smoke stacks
- Dockerized live smoke workflow (`.github/workflows/live-smoke.yml`): compose run of `simple_app` with curl assertions of real engine behavior (XSS block, traversal block, 413 body cap, passthrough)
- Upstream drift guard (`.github/workflows/upstream-drift.yml`): daily test suite run against `guard-core-rs@master`
- Security audit workflow (`cargo deny`), release gate (fmt/clippy/test at tag on stable and MSRV 1.92, tag/version consistency), automated crates.io publish on GitHub release via `CARGO_REGISTRY_TOKEN`
- `Makefile` (`install`, `test`, `lint`, `fix`, `bump-version`, `clean`) and `.github/scripts/bump_version.py` (stdlib-only version bump across the crate, example pins, `Cargo.lock`, and a CHANGELOG scaffold)

### Changed

- `guard-core-engine` dependency pinned to the published 4.0.4 release (path dep kept for local builds and CI against a sibling `guard-core-rs` checkout)
