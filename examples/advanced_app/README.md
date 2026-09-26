# advanced_app

Production-shaped guarded Rocket application. Compared to
[simple_app](../simple_app) it demonstrates the two knobs a real deployment
tunes: environment-driven engine configuration and route-scoped guard
configuration.

## What is production-shaped here

- **Env-driven engine configuration.** The engine `DetectConfig` and the
  adapter body cap are read from environment variables at startup (see the
  table below), so tuning detection needs no rebuild.
- **The per-route enforcement split, made explicit.** Guarded routes
  (`BlockGuard` / `GuardBody`) refuse threats, `/health` is excluded (no guard
  argument), and `/open` is scanned but deliberately not blocked. Rocket
  fairings are global and the adapter stores one verdict per request, so
  route-scoped guard configuration is not expressible; see the
  tower/axum/actix advanced examples for that demo.
- **No 404 leaks.** A threat to a path that matches no route is answered with
  the guarded `400` (the fairing rewrites the `404`), so probe traffic never
  reveals route inventory.

## Configuration

| Variable | Meaning | Default |
|---|---|---|
| `APP_ADDR` | Listen address | `0.0.0.0:8080` |
| `GUARD_MAX_CONTENT_LENGTH` | Engine `max_content_length` | `10000` |
| `GUARD_MAX_FULL_SCAN_BYTES` | Engine `max_full_scan_bytes` (also the default body cap) | `262144` |
| `GUARD_PRESERVE_ATTACK_PATTERNS` | Engine `preserve_attack_patterns` | `true` |
| `GUARD_SEMANTIC_THRESHOLD` | Engine `semantic_threshold` | `0.7` |
| `GUARD_THREAT_SCORE_THRESHOLD` | Engine `threat_score_threshold` (general routes) | `1.0` |
| `GUARD_BODY_CAP` | Adapter body buffering cap | `GUARD_MAX_FULL_SCAN_BYTES` |
| `GUARD_ADMIN_THREAT_SCORE_THRESHOLD` | Threat-score threshold for the `/admin` guard tree | half the general threshold |

## Routes

| Route | Guard tree | Behavior |
|---|---|---|
| `GET /health` | excluded | `200 ok` |
| `GET /` | general | `200`, greeting text |
| `GET /search?q=...` | general | `200`, or `400` on a threat |
| `POST /echo` | general | echoes the body; `400`/`413` from the guard |
| `GET /admin/stats` | guarded | `200 stats` |
| `GET /open` | none (scanned, not blocked) | `200`, even for flagged requests |
| anything else | fairing rewrite | a block on an unmatched path answers the guarded refusal shape |

## Not demonstrated (engine surface)

guard-core-rs currently ships the CPU-bound detection pipeline only. There is
no rate limiter, ban manager, IP intelligence, or Redis surface to drive, so
this example has no per-endpoint rate limits, admin ban/unban routes, or
`REDIS_URL` wiring. When the engine gains those capabilities, the admin route
tree is the natural place to hang the ban manager behind.

## Running

```sh
docker compose -f examples/advanced_app/docker-compose.yml up --build -d --wait
```

The compose stack builds the example from the repository root and pulls the
engine source from the sibling checkout at `../guard-core-rs` (a compose
`additional_contexts` entry named `engine`). Set `SMOKE_PORT` to remap the
host port.

Run natively instead (requires the sibling `../guard-core-rs` checkout):

```sh
cargo build -p rocket-guard-advanced-app
GUARD_BODY_CAP=65536 ROCKET_ADDRESS=127.0.0.1 ROCKET_PORT=8080 target/debug/rocket-guard-advanced-app
```

## Local assertions

| Assertion | Expected |
|---|---|
| `GET /health` | `200` |
| `GET /admin/stats` | `200` |
| `GET /search?q=<script>alert(1)</script>` | `400`, body `Suspicious activity detected` |
| `POST /echo` with a body over `GUARD_BODY_CAP` | `413`, body `Payload too large` |
| `POST /echo` with a small body | `200`, body echoed |

Tear down with:

```sh
docker compose -f examples/advanced_app/docker-compose.yml down -v --remove-orphans
```
