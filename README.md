# 7Board

This repository is the first Rust canary slice for the 7Board migration. It serves a low-overhead admin shell, a bounded WebSocket heartbeat and explicit readiness states. It does not claim production Xboard data or administrator acceptance until the MySQL shadow reader is wired and authenticated.

## Local

```powershell
$env:SEVENBOARD_BUILD_ID = 'local'
cargo test --locked
cargo run --release
```

The default listener is `127.0.0.1:18120`. `/healthz` is a liveness check. `/readyz` intentionally returns `503` while `SEVENBOARD_DB_MODE=unconfigured`; this prevents a canary from being mistaken for a production database deployment.

## Design constraints

- Rust/Tokio is the only canary runtime; PHP, Swoole, Octane, Horizon and Redis are not required.
- MySQL is the first production compatibility target. SQLite is reserved for local single-process fixtures; PostgreSQL remains an isolated migration candidate.
- The browser renders a fixed virtual window over 100,000 synthetic rows; synthetic rows never enter production storage.
- WebSocket payloads are heartbeat-only and use a bounded broadcast channel. The real node state protocol is added after the MySQL read model and authentication gates pass.
