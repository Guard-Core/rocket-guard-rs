# Installation

## Requirements

- Rust 1.92 or later (the crate uses edition 2024)
- Rocket 0.5

## Add the crate

```bash
cargo add rocket-guard-rs
```

or add it to your `Cargo.toml` directly:

```toml
[dependencies]
rocket-guard-rs = "1.0.0"
rocket = "0.5.1"
```

`rocket-guard-rs` `1.0.0` depends on `guard-core-engine` `4.0.4`, the
published detection engine crate. The adapter's version pin stays in lockstep
with the published engine release.

## Verify the installation

A minimal application that attaches the fairing and protects two routes:

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

With the server running:

```bash
curl -i http://127.0.0.1:8080/health
curl -i 'http://127.0.0.1:8080/submit?cmd=$(whoami)'
```

The first request answers `200 OK`; the second is blocked by the engine with
`400 Bad Request` and a `Suspicious activity detected` body.

## Building from source

The repository itself consumes the engine as a local path dependency on a
sibling `guard-core-rs` checkout (see the repository README), so building the
repository workspace locally requires that checkout to exist. Downstream
applications that depend on the published crate are not affected: crates.io
resolves `guard-core-engine` automatically.
