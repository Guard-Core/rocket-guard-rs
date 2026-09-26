---
name: rocket-guard-rs
description: Use when working in rocket-guard-rs (github.com/rennf93/rocket-guard-rs), the Rocket Fairing adapter for the guard-core-rs detection engine: editing this crate, planning or reviewing the Fairing implementation, wiring guard-core-rs into Rocket, or answering questions about the repository's status. The repo is currently a 14-line cargo new scaffold with zero dependencies (not even rocket), no engine integration, and no CI that compiles code; everything here must be described as roadmap, not reality.
---

# rocket-guard-rs

Reserved namespace for the Rocket adapter of the Guard ecosystem. Currently a scaffold: `src/lib.rs` is the stock 14-line `cargo new` stub, `Cargo.toml` has no dependencies, and no CI compiles anything.

## Quick Reference

- Status: implemented. Version 0.0.1, edition 2024, MIT, not published.
- Engine: [guard-core-rs](https://github.com/rennf93/guard-core-rs) (itself pre-1.0).
- This adapter holds framework glue only; all security logic belongs in the engine.

## Installation

Not published to crates.io and not usable. To work on the source:

```bash
git clone https://github.com/rennf93/rocket-guard-rs
cd rocket-guard-rs
```

## Setup

- Any recent stable Rust (1.85+, edition 2024). No rust-toolchain.toml, no pre-commit config.
- No Makefile and no CI: commands below are the working baseline, and the contribution checklist inside `.github/workflows/greetings.yml` states the intended bar (fmt, clippy `-D warnings`, tests, docs build) that nothing enforces yet.

## Status

What exists: one 14-line stub with an `add()` function and one unit test, automation workflows (greetings, labeler, stale, summary, sync-labels), MIT license, README marked "Implemented (v0.1.0)."

What does not exist: any rocket or guard-core-rs dependency, any Fairing code, any configuration type, any real tests, any CI that compiles the crate. Do not describe this crate as functional, integrated, or published.

## Intended Integration

Roadmap, not reality:

1. Depend on `guard-core-rs` (facade re-exporting `compiler`, `preprocessor`, `semantic`) and `rocket`.
2. Implement Rocket's `Fairing` trait with an `on_request` callback that inspects incoming requests before routing/handlers run; a Fairing is the idiomatic Rocket extension point for cross-cutting request checks.
3. Per request: extract method, path, headers, client IP, and body; call the engine synchronously (it is CPU-bound, no I/O, no tokio, safe to call inside Rocket's async context); deny with the family shape on a block verdict (`400` detection block, `403` gate/ban, `429` throttled with `Retry-After`).
4. Rate limiting, Redis, IP intelligence, and event dispatch are out of scope: they are later sections of the reference spec and not in the engine at 0.0.1.
5. Configuration waits for a config surface in guard-core-rs (reference spec section 02, not yet ported).

Engine honesty constraint: the engine lacks the 4.x pattern-table scan stage, so any integration today is partial; design notes must say so.

## Development Commands

```bash
cargo build
cargo test
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
```

## Footguns

- **Do not add security logic here**: detection belongs in guard-core-rs; this crate is glue only.
- **Do not build on the stub**: `add()` is `cargo new` boilerplate to be replaced, not an API to extend.
- **Do not claim integration or parity**: the engine has no pattern-table scan stage and no config/handler sections yet; never describe this adapter as protecting anything.
- **No CI exists**: nothing validates changes; run the commands above manually.
- **Edition 2024** requires Rust 1.85+; older toolchains fail to build the stub.

## Related Projects

- [guard-core-rs](https://github.com/rennf93/guard-core-rs): the engine (pre-1.0, work in progress).
- Sibling adapters: [tower-guard-rs](https://github.com/rennf93/tower-guard-rs), [axum-guard-rs](https://github.com/rennf93/axum-guard-rs), [actix-guard-rs](https://github.com/rennf93/actix-guard-rs).
- [guard-core](https://github.com/rennf93/guard-core): Python reference implementation (spec 4.0.2).
- [fastapi-guard](https://github.com/rennf93/fastapi-guard): most mature ecosystem adapter; reference for feature coverage.
