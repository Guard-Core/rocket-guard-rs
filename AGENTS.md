# AGENTS.md
Guidance for AI agents (including Claude Code) working in this repository.

## Project Overview

rocket-guard-rs is the Rocket adapter for the Guard ecosystem. It screens Rocket 0.5 traffic through the [guard-core-rs](https://github.com/Guard-Core/guard-core-rs) detection engine: [`GuardFairing`](src/fairing.rs) scans path, query, and header views in `on_request` and stashes the verdict in request-local state, and per-route request guards ([`BlockGuard`](src/guards.rs) for bodyless routes, [`GuardBody`](src/guards.rs) for routes with a body) enforce the verdict before a handler runs. It contains no security logic of its own.

- **Repository**: https://github.com/Guard-Core/rocket-guard-rs
- **Language**: Rust, edition 2024, MSRV 1.92
- **License**: MIT OR Apache-2.0
- **Version**: 1.2.0 (published to crates.io)
- **Status**: implemented, tested, and published. The engine is a path dependency into a sibling `guard-core-rs` checkout; note the crates.io yank below (see [Engine Dependency](#engine-dependency)).

## Ecosystem Position

```
guard-core (Python)     <- Reference implementation, spec owner (spec 4.1.0)
└── guard-core-rs       <- Rust engine crate: guard-core-engine (detect, preprocessor, semantic, compiler)
    ├── tower-guard-rs  <- Framework-agnostic tower Layer + Service
    ├── axum-guard-rs   <- Sibling adapter (composes tower-guard-rs)
    ├── actix-guard-rs  <- Sibling adapter (Transform + Service)
    └── rocket-guard-rs (this) <- Rocket Fairing + request guards
```

The engine crate stays framework-free (no I/O, no tokio, no framework types). This repository is the opposite side of that boundary: framework glue only. No security logic belongs here; it belongs in guard-core-rs.

## Why the two-piece wiring

Rocket has no middleware chain that can abort a request: `on_request` in a fairing has no outcome return, and a fairing can only peek at the first 512 bytes of a body (`Data::peek` is capped at `PEEK_BYTES`). The adapter therefore splits the work the way Rocket requires:

1. **`GuardFairing`** (`Kind::Ignite | Kind::Request | Kind::Response`): `on_ignite` registers the `400`/`403`/`413`/`429`/`500` catchers (never over an application-claimed status; Rocket treats same-code catchers at the same base as a fatal collision), `on_request` scans the metadata views and stashes the verdict, `on_response` rewrites a `404` to the guarded `403` when the verdict is a threat (a `404` proves no handler ran, so the rewrite cannot discard work).
2. **Guard arguments on protected routes**: `BlockGuard` for routes without a body, `GuardBody` for routes with one (it buffers up to the cap, scans the body view, and hands the bytes to the handler in one step, because Rocket's `Data` is a one-shot stream).

A route without a guard argument is scanned but never blocked; that is Rocket's own per-route opt-in model. Fail-secure rule: a guard that cannot find a stashed verdict refuses with `500` rather than passing uninspected. The body view is never scanned by the fairing: a truncated scan would be a bypass vector.

## Engine Integration

`guard-core-engine` exposes exactly one detection entry point, which this adapter calls once per request view:

```rust
pub fn detect(content: &str, request_context: &str, config: &DetectConfig) -> DetectVerdict
```

`DetectConfig` has five public fields and **no `Default` impl**; the ecosystem defaults are pinned in `crate::default_config()` (10 000 / 262 144 / true / 0.7 / 1.0), matching the conformance corpus knobs. `DetectVerdict` carries `is_threat`, `threat_score`, `threats`, `original_length`, `processed_length` and **no response shape at all**: the `403`/`413`/`500` translation lives in this adapter (`src/response.rs`) and follows the ecosystem's plain-text error convention (the bare message, `text/plain; charset=utf-8`).

View mapping (documented in `src/lib.rs` and `src/scan.rs`):

| Request part | Context | Evaluated |
|---|---|---|
| `request.path()` | `url_path` | in the fairing, when not `/` |
| `request.query()` | `query_param` | in the fairing, when non-empty |
| header values | `header` | in the fairing, when the name is not excluded |
| buffered body | `request_body` | in `GuardBody`, when non-empty after lossy UTF-8 decode |

The method is not scanned: `detect` has no method parameter. Non-UTF-8 header values are skipped (they cannot be represented as `&str`).

## Engine Dependency

- `Cargo.toml` pins `guard-core-engine` and `guard-core-rs` at 4.2.0 with paths into the sibling checkout (`../guard-core-rs/crates/guard-core-engine`, `../guard-core-rs/crates/guard-core-rs`).
- Registry note, stated plainly: the 4.1.0 dists were yanked (the version-accuracy fix for the family tag mistake), so 1.1.0 could not resolve its engine from the registry alone; the synchronized 4.2.0 train restores resolution (`rocket-guard-rs` 1.2.0 over `guard-core-engine`/`guard-core-rs` 4.2.0).
- The engine crate is used directly for `detect`; the facade dependency supplies the pipeline-side modules (events, geo, cloud provider, responses, and the rate-limit/ban stage wiring). The facade re-exports the full engine stage set since 4.1.0.
- CI checks out `Guard-Core/guard-core-rs` (branch `master`, moving branch by design, documented in `.github/workflows/ci.yml`) into `../guard-core-rs` before building, mirroring `tower-guard-rs`. Do not replace that with a git dependency without updating the CI comment and this file.

## Development Commands

CI is the source of truth (`.github/workflows/*.yml`); there is no Makefile.

```bash
cargo check --all-targets                              # type check
cargo fmt --all -- --check                             # format gate
cargo clippy --all-targets -- -D warnings              # lint gate (pedantic is warn, so -D warnings enforces it)
cargo test                                             # unit + integration + doctests (workspace: adapter + examples)
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps         # rustdoc gate
cargo deny check                                       # advisories, licenses, bans, sources (deny.toml)
```

A sibling `guard-core-rs` checkout at `../guard-core-rs` is required for every command.

The example apps under `examples/` build and run like any workspace member:

```bash
docker compose -f examples/simple_app/docker-compose.yml up --build -d --wait    # live smoke stack
SMOKE_PORT=8091 docker compose -f examples/simple_app/docker-compose.yml up ...   # remapped host port
```

The compose stacks also need the sibling `../guard-core-rs` checkout: the
Dockerfile receives the engine source through a compose
`additional_contexts` entry named `engine` pointing at `../../../guard-core-rs`
(relative to the compose file). The `live-smoke` workflow runs the simple_app
stack and the full curl assertion matrix on every push/PR; `upstream-drift`
runs the suite daily against a fresh `guard-core-rs@master` checkout placed at
the path dependency location. `security.yml` runs `cargo deny check` on
push/PR and weekly. `release.yml` gates `v*` tag pushes with the full suite
plus a tag/version consistency check; crates.io publishing is manual and
owner-gated.

## Project Structure

```
rocket-guard-rs/
├── Cargo.toml / Cargo.lock          # adapter package + workspace (examples are members)
├── deny.toml                        # cargo-deny: advisories, licenses, bans, sources
├── src/
│   ├── lib.rs        # crate docs, GuardFairing re-export, default_config
│   ├── fairing.rs    # GuardFairing: on_ignite catchers, on_request scan, on_response 404 rewrite
│   ├── guards.rs     # BlockGuard + GuardBody: per-route enforcement and body scan
│   ├── scan.rs       # GuardEngine, verdict stash, EXCLUDED_HEADERS
│   └── response.rs   # 403/413/500 builders and their public message constants
├── tests/integration.rs  # Rocket local-client behavior tests through the public API
├── examples/
│   ├── simple_app/      # minimal guarded Rocket app: main.rs, Dockerfile, compose, README
│   └── advanced_app/    # env-driven config, per-route opt-in demo: main.rs, Dockerfile, compose, README
└── .github/
    ├── workflows/ci.yml             # push/PR: fmt, clippy, test, doc, MSRV
    ├── workflows/security.yml       # push/PR + weekly: cargo deny check
    ├── workflows/live-smoke.yml     # push/PR: dockerized simple_app smoke with curl assertions
    ├── workflows/upstream-drift.yml # daily: suite against guard-core-rs@master
    ├── workflows/release.yml        # v* tag gate: matrix test + tag/version consistency
    └── workflows/issue-link.yml     # PRs must reference an open issue
```

## Testing

- `cargo test` runs the unit tests (`src/`), the integration tests (`tests/integration.rs`, Rocket local client), and the doctests. All must pass.
- Coverage must include: benign passthrough, threats blocked via `BlockGuard` and via `GuardBody`, engine panic to `500` (the `#[cfg(test)]` detector seam), the 404-to-403 rewrite, catcher non-collision, body cap `413`, and per-route opt-in (a route without a guard argument is not blocked).
- Payloads must come from the spec 4.1.0 conformance corpus (`guard-core-rs/conformance/guard-core-spec-4.1.0/cases/`) so they are guaranteed threats, not guesses.

## Code Quality Standards

- `[lints]` in `Cargo.toml`: `unsafe_code = "forbid"`, `clippy::all = "deny"`, `clippy::pedantic = "warn"` (enforced as errors by CI's `-D warnings`). `clippy::nursery` is deliberately not enabled: its lints drift between clippy versions.
- No `#[allow(...)]` in `src/`.
- rustdoc warnings are errors in CI.

## Best Practices

1. **Keep the engine call surface unchanged.** Every request goes through the fairing scan and, for bodies, through `GuardBody`; both recover engine panics into `500`. Do not bypass the recovery.
2. **Do not weaken fail-secure.** Any new failure path must map to `500` or a documented rejection, never to an uninspected passthrough.
3. **Run the full local gate before committing**: fmt, clippy, test, doc, cargo deny. CI runs all five.
4. **Example apps are part of the workspace.** `examples/simple_app` and `examples/advanced_app` build with a plain `cargo build` from the repo root; when you change the adapter's public API or response shapes, update the examples and their READMEs (and re-run the live smoke assertions) in the same change.
5. **Conventional commits** (`feat:`, `fix:`, `docs:`, `ci:`), matching history. No AI attribution in commit messages.
6. **Document status honestly.** This crate is published at 1.1.0, but its engine dependency is currently unresolvable from the registry alone (4.1.0 yanked); say so rather than implying a plain `cargo add` works. crates.io publishing is manual and owner-gated; the release workflow only gates the tag.
7. **Keep the engine surface claims honest.** The engine ships the detect pipeline plus the in-memory rate limiter, ban store, geo country rules, cloud provider checks, and distributed store traits (Redis backends are wired by the consumer, not bundled). Do not document capabilities the engine does not expose.

## Related Projects

- [guard-core-rs](https://github.com/Guard-Core/guard-core-rs): Rust detection engine (this crate's dependency).
- Sibling adapters: [tower-guard-rs](https://github.com/Guard-Core/tower-guard-rs), [axum-guard-rs](https://github.com/Guard-Core/axum-guard-rs), [actix-guard-rs](https://github.com/Guard-Core/actix-guard-rs).
- [guard-core](https://github.com/Guard-Core/guard-core): Python reference implementation and spec owner (spec 4.1.0).
- [fastapi-guard](https://github.com/Guard-Core/fastapi-guard): the most mature adapter in the ecosystem, a useful reference for feature coverage.
