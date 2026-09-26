# Examples

The repository ships two runnable applications under
[`examples/`](https://github.com/rennf93/rocket-guard-rs/tree/master/examples).
Both use the real adapter surface: `GuardFairing` attached once, plus a
`BlockGuard` or `GuardBody` argument on every protected route (Rocket's own
enforcement mechanism).

The example crates are workspace members and build against the in-repository
path dependency, so building them locally requires a sibling `guard-core-rs`
checkout (see the repository README).

## simple_app

A minimal guarded Rocket application
([`examples/simple_app`](https://github.com/rennf93/rocket-guard-rs/tree/master/examples/simple_app)):

| Route | Guard | Behavior |
|---|---|---|
| `GET /health` | none (excluded) | `200 ok`; scanned by the fairing but never blocked |
| `GET /` | `BlockGuard` | `200` greeting |
| `GET /search?q=...` | `BlockGuard` | `200 search ok`, or `400` when the query trips the engine |
| `POST /echo` | `GuardBody` | echoes the body; `400` for a threat, `413` over the body cap |

The `/health` route carries no guard argument, which is the Rocket-shaped
excluded path: the fairing still scans it (request fairings see every
request), but without a guard argument nothing can refuse the request.

Run it:

```bash
cargo run -p rocket-guard-simple-app
```

## advanced_app

A production-shaped guarded application
([`examples/advanced_app`](https://github.com/rennf93/rocket-guard-rs/tree/master/examples/advanced_app))
that demonstrates environment-driven engine configuration and the per-route
enforcement split: guarded routes (`BlockGuard` / `GuardBody`) refuse
threats, `/health` is excluded (no guard argument), and `/open` is scanned
but deliberately not blocked. A threat to a path that matches no route is
answered with the guarded `400` (the fairing rewrites the `404`), so probe
traffic never reveals route inventory.

Note that route-scoped guard configuration is not expressible in this
adapter: Rocket fairings are global and the adapter stores one verdict per
request. See the tower/axum/actix advanced examples for that demo.

### Configuration

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

### Routes

| Route | Guard tree | Behavior |
|---|---|---|
| `GET /health` | excluded | `200 ok` |
| `GET /` | general | `200`, greeting text |
| `GET /search?q=...` | general | `200`, or `400` on a threat |
| `POST /echo` | general | echoes the body; `400`/`413` from the guard |
| `GET /admin/stats` | guarded | `200 stats` |
| `GET /open` | none (scanned, not blocked) | `200`, even for flagged requests |
| anything else | fairing rewrite | a block on an unmatched path answers the guarded refusal shape |

Run it directly or with the provided Docker setup:

```bash
cargo run -p rocket-guard-advanced-app
```

```bash
cd examples/advanced_app
docker compose up
```
