# Contributing to Rocket Guard

Thanks for considering a contribution to Rocket Guard, part of the Guard ecosystem (rocket-guard-rs follows the conventions of the Python baseline: guard-core and fastapi-guard).

## Development Setup

Requirements:

- Rust 1.92 (MSRV, what CI gates on) or newer; rustup recommended

## Sibling path dependencies

rocket-guard-rs depends on the engine as a path dependency (`../guard-core-rs`). CI checks the sibling out
automatically; locally, clone the engine next to this repository (side by side in the same
directory):

```bash
git clone https://github.com/rennf93/guard-core-rs ../guard-core-rs

cargo build
cargo test
```

## Quality Gates

Run before pushing (CI enforces the same checks):

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo doc --no-deps
```

## Pull Requests

- Every PR closes an open issue ("Delivers issue: #N") or carries the `no-issue` label (chores and dependency bumps).
- Keep the CI green; one clean push per PR is preferred.
- Commit messages: lowercase, imperative, conventional style (`fix(scope): ...`, `feat(scope): ...`, `ci(scope): ...`). No attribution trailers.

## Security

Never open public issues for security vulnerabilities. Follow SECURITY.md and report via GitHub security advisories.

## Questions

Open a GitHub Discussion in this repository or ask in the Guard Discord (#help).
