//! Minimal guarded Rocket application, using the real adapter surface:
//! [`rocket_guard_rs::GuardFairing`] attached once, plus a
//! [`rocket_guard_rs::BlockGuard`] or [`rocket_guard_rs::GuardBody`] argument
//! on every protected route (Rocket's own enforcement mechanism).
//!
//! Routes:
//!
//! | Route | Guard | Behavior |
//! |---|---|---|
//! | `GET /health` | none (excluded) | `200 ok`; scanned by the fairing but never blocked |
//! | `GET /` | `BlockGuard` | `200` greeting |
//! | `GET /search?q=...` | `BlockGuard` | `200 search ok`, or `400` when the query trips the engine |
//! | `POST /echo` | `GuardBody` | echoes the body; `400` for a threat, `413` over the body cap |
//!
//! The `/health` route carries no guard argument, which is the Rocket-shaped
//! excluded path: the fairing still scans it (request fairings see every
//! request), but without a guard argument nothing can refuse the request.
//! That is the same effect the Python distro's excluded-paths configuration
//! has.

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
    "rocket-guard-rs simple app"
}

#[get("/search?<q>")]
fn search(_guard: BlockGuard, q: &str) -> String {
    format!("search ok: {q}")
}

#[post("/echo", data = "<body>")]
fn echo(_guard: BlockGuard, body: GuardBody) -> Vec<u8> {
    body.into_inner()
}

#[rocket::launch]
fn rocket() -> _ {
    rocket::build()
        .attach(GuardFairing::new(default_config()))
        .mount("/", routes![health, root, search, echo])
}
