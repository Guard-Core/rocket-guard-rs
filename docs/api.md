# API reference

The public surface of `rocket_guard_rs` `1.0.0`. The full crate documentation
is also in `src/lib.rs` (build it with `cargo doc --open`).

## Fairing

### `GuardFairing`

The Rocket fairing that screens every request and registers the refusal
catchers. Attach it once on `rocket::build()`:

```rust
rocket::build().attach(rocket_guard_rs::GuardFairing::new(config))
```

Attach with `Kind::Ignite | Kind::Request | Kind::Response` (the default
`Kind` set the fairing declares): `on_ignite` registers the
`400`/`403`/`413`/`429`/`500` catchers, `on_request` runs the IP gate, the
stateful stage (dynamic bans, then rate limiting), and the path, query, and
header views, stashing the verdict in request-local state, and
`on_response` supports the `404` rewrite described below.

Constructors and builders:

| Method | Description |
|---|---|
| `GuardFairing::new(config: DetectConfig)` | Build the fairing from an engine `DetectConfig`. The body cap starts at `config.max_full_scan_bytes` |
| `GuardFairing::with_defaults()` | Build the fairing with `default_config()` |
| `.with_body_cap(body_cap: usize)` | Replace the body buffering cap, in bytes. A body larger than the cap is refused with `413` rather than forwarded unscanned |
| `.with_ip_gate(ip_gate: IpGateConfig)` | Install the global IP gate (see below) |
| `.with_rate_limiting(limiter: RateLimiter)` | Install the rate limiter (see below) |
| `.with_ip_banning(manager: IpBanManager, config: IpBanConfig)` | Install the dynamic ban store and the auto-ban engine (see below) |

Routes without a guard argument are only scanned, not blocked: in Rocket,
protection is per-route, and that is what the guard argument is for. When the
verdict is a block (a threat, an IP-gate denial, a live ban, an auto-ban
firing, or a rate-limit crossing) and the request would otherwise answer
`404`, the fairing rewrites the `404` to that verdict's family shape so probe
traffic never reveals route inventory.

### The IP gate: `IpGateConfig`

Built with `IpGateConfig::new(whitelist, blacklist, exempt_ips)`, which fails
closed on an invalid entry (`IpGateError` names the list and the entry):

```rust
use rocket_guard_rs::{GuardFairing, IpGateConfig};

let gate = IpGateConfig::new(
    [] as [&str; 0],
    ["203.0.113.9"],
    ["198.51.100.7", "198.51.100.16/28"],
)
.expect("valid lists");
let fairing = GuardFairing::with_defaults().with_ip_gate(gate);
```

The gate runs in `on_request` before the metadata scan, on the request's
client IP: a blacklisted IP - or an IP a non-empty `whitelist` matches
neither directly nor through `exempt_ips` - is refused with `403 Forbidden`
(the `Forbidden` body), both through the guards and through the `404` rewrite
for unrouted paths. A request whose client IP is unknown (Rocket's local test
client, for example) is not attributed: the gate does not run and the scan
runs unconditionally.

**exempt_ips vs whitelist.** `exempt_ips` is noise reduction for
known-friendly automation (monitoring probes, VPN egress, a partner's
server), not immunity: it sets the same skip state a whitelist match sets but
never adds a deny path and never opens the whitelist gate. The blacklist,
bans-style checks, and detection still apply to exempt IPs - an attack
payload from an exempt IP is still `400 Suspicious activity detected`. The
stateful stages (`GuardFairing::with_rate_limiting`,
`GuardFairing::with_ip_banning`) skip exactly what the reference skips for a
whitelist match (`is_whitelisted || is_exempt`): rate limiting, violation
counting, and banning. Detection never skips anything.

### The rate limiter: `RateLimiter`

```rust
use rocket_guard_rs::{GuardFairing, RateLimitConfig, RateLimiter};

let limiter = RateLimiter::new(RateLimitConfig {
    enable_rate_limiting: true,
    rate_limit: 30,
    rate_limit_window: 10,
    ..RateLimitConfig::default()
})
.expect("valid config");
let fairing = GuardFairing::with_defaults().with_rate_limiting(limiter);
```

The limiter's constructor fails closed on a zero limit or window. Installed
with `GuardFairing::with_rate_limiting`, it runs in `on_request` after the IP
gate and the ban stage, before the metadata scan: a crossing is refused with
`429 Too Many Requests` carrying `Retry-After: <window seconds>`. With
`enable_rate_limit_auto_ban` on and IP banning configured, every crossing
counts one `rate_limit` violation toward the auto-ban engine; the response
stays `429` and the ban bites on the next request. Requests without a client
IP cannot be attributed and are not rate limited; detection still screens
them. The limiter is shared with the managed engine state and clone-shares
its window store, so out-of-band handles (stats, admin resets) work
alongside the installed fairing.

### The ban stage: `IpBanManager` + `IpBanConfig`

```rust
use rocket_guard_rs::{GuardFairing, IpBanConfig, IpBanManager, ThreatBanEntry};

let manager = IpBanManager::new();
let config = IpBanConfig::new(
    true,
    10,
    3600,
    [("sqli", ThreatBanEntry { threshold: 3, duration: 1800 })],
)
.expect("valid config");
let fairing = GuardFairing::with_defaults().with_ip_banning(manager, config);
```

The config constructor fails closed on an invalid `threat_ban_config` entry.
Installed with `GuardFairing::with_ip_banning`, the ban check runs in
`on_request` before the limiter: a live ban is refused with `403 Forbidden`
(`IP address banned`) and banned traffic never consumes rate budget. Every
detected threat counts its categories per client IP (the reference
pipeline's suspicious-activity stage), and a crossed `threat_ban_config`
entry or the flat `auto_ban_threshold` bans on the spot, answering
`403 Forbidden` (`IP has been banned`); without a crossing the block keeps
the `400 Bad Request` (`Suspicious activity detected`) shape.
`config.enable_ip_banning = false` counts violations but never bans.
Whitelisted and exempt IPs are never counted, so they can never be
auto-banned. The store pair is shared with the managed engine state and
clone-shares its stores.

### Catchers

`guard_catchers() -> Vec<Catcher>` returns the
`400`/`403`/`413`/`429`/`500` catchers that render refusals as the
ecosystem's plain-text error shape (the throttled shape carries the
`Retry-After` header). The fairing registers them itself, skipping any
status the application already registered a catcher for (Rocket treats
same-code catchers at the same base as a fatal collision).

## Guards

### `BlockGuard`

A request guard for routes without a body argument:

```rust
use rocket::get;
use rocket_guard_rs::BlockGuard;

#[get("/health")]
fn health(_guard: BlockGuard) -> &'static str {
    "hello"
}
```

It enforces the verdict stashed by the fairing: a threat answers `400`, a
gate denial, live ban, or auto-ban answers `403`, a rate-limit crossing
answers `429` (with `Retry-After`), and a failed check answers `500`.
Fail-secure rule: if the guard cannot find a verdict, the security system is
not running, and the request is refused rather than passed uninspected.

### `GuardBody`

The scanned request body, usable as a data guard. Buffering, scanning, and
handing the body to the handler are fused into one data guard because
Rocket's `Data` is a one-shot stream:

```rust
use rocket::post;
use rocket_guard_rs::GuardBody;

#[post("/submit", data = "<body>")]
fn submit(body: GuardBody) -> Vec<u8> {
    body.into_inner()
}
```

As a data argument (`data = "<body>"`), it refuses the request on any of the
fairing's metadata views and scans the body itself. The body is buffered up
to the cap configured on `GuardFairing::with_body_cap` (default: the engine's
full-scan cap, 262,144 bytes). Rocket's own per-guard `limits` still apply to
whatever the handler does with the scanned bytes afterwards.

Methods:

| Method | Description |
|---|---|
| `.into_inner() -> Vec<u8>` | Consume the guard and return the scanned bytes |
| `.as_slice() -> &[u8]` | Borrow the scanned bytes |

### `GuardBodyError`

The error type produced when the body cannot be buffered or scanned.

## Configuration

### `default_config()`

Returns the reference default `DetectConfig`:

| Knob | Value |
|---|---|
| `max_content_length` | `10_000` |
| `max_full_scan_bytes` | `262_144` |
| `preserve_attack_patterns` | `true` |
| `semantic_threshold` | `0.7` |
| `threat_score_threshold` | `1.0` |

### `DetectConfig`

Re-exported from `guard_core_engine::detect`. Fields:

| Field | Type | Meaning |
|---|---|---|
| `max_content_length` | `usize` | Semantic budget and truncation budget |
| `max_full_scan_bytes` | `usize` | Preprocessor full-scan cap (also the default body cap) |
| `preserve_attack_patterns` | `bool` | Keep attack patterns in the processed view |
| `semantic_threshold` | `f64` | Semantic analysis threshold |
| `threat_score_threshold` | `f64` | Threat score threshold for a verdict |

## Behavior

### What it inspects

One engine call per request view:

| Request part | Engine context | Notes |
|---|---|---|
| Path | `url_path` | Skipped for `/` |
| Query string | `query_param` | Skipped when empty |
| Header values | `header` | Skips `sec-*` and the negotiation/routing headers |
| Body | `request_body` | Buffered by `GuardBody`, capped |

The HTTP method is not scanned.

### Responses

| Situation | Status | Body |
|---|---|---|
| The IP gate denies the client IP | `403 Forbidden` | `Forbidden` |
| A live ban on the client IP | `403 Forbidden` | `IP address banned` |
| Rate limit crossed | `429 Too Many Requests` (+ `Retry-After: <window>`) | `Too many requests` |
| Engine flags a view | `400 Bad Request` | `Suspicious activity detected` |
| Engine flags a view and a crossed auto-ban threshold bans on the spot | `403 Forbidden` | `IP has been banned` |
| Body exceeds the cap | `413 Payload Too Large` | `Payload too large` |
| Body read error or engine panic | `500 Internal Server Error` | `Security check failed` |

The adapter is fail-secure: any failure to complete the security check
answers `500`, never an uninspected passthrough. Engine panics are caught
with `catch_unwind` (note that `panic = "abort"` in a release profile
disables that recovery).

### Constants

Re-exported refusal message bodies:

| Constant | Value |
|---|---|
| `BLOCKED_MESSAGE` | `"Suspicious activity detected"` |
| `FORBIDDEN_MESSAGE` | `"Forbidden"` |
| `BANNED_MESSAGE` | `"IP address banned"` |
| `ACTIVITY_BANNED_MESSAGE` | `"IP has been banned"` |
| `RATE_LIMITED_MESSAGE` | `"Too many requests"` |
| `OVERSIZE_MESSAGE` | `"Payload too large"` |
| `FAILURE_MESSAGE` | `"Security check failed"` |

### Engine re-exports

`DetectConfig`, `DetectVerdict`, and `Threat` are re-exported from
`guard_core_engine::detect`.

`IpGateConfig`, `IpGateDecision`, `IpGateDenial`, `IpGateError`, and
`IpGateVerdict` are re-exported from `guard_core_engine::ip_gate`. A
`DetectVerdict` carries `is_threat`, a `threat_score`, and the list of
`Threat` findings (regex or semantic).

`RateLimiter`, `RateLimitConfig`, `RateLimitConfigError`, and
`RateLimitDecision` are re-exported from `guard_core_engine::rate_limit`.

`IpBanManager`, `IpBanConfig`, `IpBanConfigError`, `BanError`, `BanRecord`,
`Clock`, `ResolvedBan`, `ThreatBanEntry`, and `ViolationCounters` are
re-exported from `guard_core_engine::ip_ban`.
