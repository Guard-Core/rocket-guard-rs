# rocket-guard-rs

`rocket-guard-rs` is application-layer security middleware for
[Rocket](https://rocket.rs) 0.5, powered by the
[guard-core-rs](https://github.com/Guard-Core/guard-core-rs) detection engine.
It is part of the [Guard ecosystem](https://github.com/Guard-Core).

The crate holds framework glue only: every detection decision comes from the
engine. [`GuardFairing`](api.md#guardfairing) screens every request through
the engine, and [`BlockGuard`](api.md#blockguard) /
[`GuardBody`](api.md#guardbody) enforce the verdict before a route handler
runs. The adapter is fail-secure: any failure to complete the security check
answers `500`, never an uninspected passthrough.

## Ecosystem position

```text
guard-core (Python)           <- Reference implementation, spec owner
├── guard-core-rs             <- Rust engine: detection, preprocessing, semantics
│   ├── tower-guard-rs        <- Adapter: tower middleware
│   ├── axum-guard-rs         <- Adapter: axum layer over tower-guard-rs
│   ├── actix-guard-rs        <- Adapter: actix-web middleware
│   └── rocket-guard-rs       <- Adapter: rocket fairing and guards (this repo)
├── guard-core-go             <- Go port
└── guard-core-ts             <- TypeScript port
```

The fairing translates native request content into engine inputs (path, query
string, header values), runs one engine call per request view, and stashes
the verdict in request-local state; the guards translate the verdict into a
native refusal.

## Wiring: two steps, because Rocket needs two

Rocket has no middleware chain that can abort a request. A fairing's
`on_request` cannot short-circuit (there is no outcome return), and a request
guard cannot read bodies. The adapter therefore splits the work the way
Rocket requires:

1. **Attach `GuardFairing`** (`Kind::Ignite | Kind::Request |
   Kind::Response`). Its `on_request` scans the path, query, and header views
   and stashes the verdict in request-local state. Its `on_ignite` registers
   the `400`/`403`/`413`/`429`/`500` catchers that render refusals as the ecosystem's
   plain-text error shape.
2. **Add a guard argument to each protected route**: `BlockGuard` for routes
   without a body, `GuardBody` for routes with one. Protection is per-route,
   and the guard argument is Rocket's own mechanism for it.

Routes without either guard argument are scanned but not blocked. The
fairing additionally rewrites a `404` to the guarded refusal shape when the verdict
is a threat, so a threat to a path that matches no route does not leak a
`404`.

## Installation

```bash
cargo add rocket-guard-rs
```

The published crate is `1.0.0` and depends on the published
`guard-core-engine` `4.0.4`. Requires Rust 1.92 or later (edition 2024) and
Rocket 0.5. See [Installation](installation.md) for details.

## Quick start

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

## What it inspects

One engine call per request view, mirroring the mapping used by the sibling
adapters:

| Request part | Engine context | Notes |
|---|---|---|
| Path | `url_path` | Skipped for `/` |
| Query string | `query_param` | Skipped when empty |
| Header values | `header` | Skips `sec-*` and the negotiation/routing headers |
| Body | `request_body` | Buffered by `GuardBody`, capped |

The HTTP method is not scanned.

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

## Where to go next

- [Installation](installation.md) for requirements and dependency setup
- [API](api.md) for the full public surface and behavior tables
- [Examples](examples.md) for runnable applications
