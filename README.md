# Throttle

A self-hosted crash report server for the SourceMod [Accelerator](https://github.com/asherkin/accelerator) extension. A single Rust binary backed by SQLite: no PHP, MySQL, Redis or cron.

This is a rewrite of [asherkin/throttle](https://github.com/asherkin/throttle). The old code is still reachable through the `php-final` tag.

## Highlights

- **Accelerator-compatible ingestion** (`POST /submit`, `POST /symbols/submit`). See [docs/protocol.md](docs/protocol.md).
- **Dump processing** in parallel with [rust-minidump](https://github.com/rust-minidump/rust-minidump), with no external binaries. 32-bit and 64-bit dumps from Windows, Linux and macOS.
- **Web UI**: crash pages (with the `Sys_Error` message and notices), dashboard, bulk delete, Steam login, sharing between users, dark/light theme.
- **Public statistics** (`/stats`): counters, crashes per hour and per day, Top Crashers with drill-down, processing performance. Charts are SVG rendered on the server.
- **Optional**: deep analysis with `carburetor`, notices, HTTP symbol fetching, Prometheus metrics.
- **Resilient by design**: it accepts cheaply and discards later, because the client never retries (see below).

## Quick start

```sh
cargo build --release
cp deploy/config.example.toml throttle.toml   # edit https (and hostname, in production)
./target/release/throttle serve
```

Without `--config`, it reads `throttle.toml` if present and otherwise uses the defaults (`127.0.0.1:8080`, data in `./data`). A `--config` (or `THROTTLE_CONFIG`) that points to a missing file is an error. Every key is optional and unknown keys are rejected, so a typo fails at startup.

Or with a container:

```sh
podman build -t throttle -f Containerfile .
podman run -p 9090:9090 -v throttle-data:/data throttle
```

Then point your game servers at it in `addons/sourcemod/configs/core.cfg`:

```text
"MinidumpUrl"        "https://throttle.example.com/submit"
"MinidumpSymbolUrl"  "https://throttle.example.com/symbols/submit"
"MinidumpAccount"    "YOUR_STEAMID64"
```

Do not set `MinidumpBinaryUrl`: this server never asks for binaries.

## Why it does not fail with "capacity reached"

The old public server answered `N|...|Sorry, crash submission is currently disabled (capacity reached)` when it filled up. The client **does not retry and deletes the local dump** on any refusal, so every refusal loses the crash forever. Here:

| Situation | What happens |
|---|---|
| Large queue or very common crash (`queue_watermark`, `dedupe_threshold`) | The presubmit answers `M`: only the metadata is uploaded |
| The same crash again (`repeat_window_days`) | The presubmit answers `M` and the upload is counted on the existing crash, without storing another dump (see [Repeats](docs/features.md#repeats)) |
| Per owner+IP limit exceeded (`rate_limit`) | `N` response with a message |
| Disk above quota (`disk_quota_bytes`) | Retention deletes the oldest, never-viewed crashes first |
| Disk nearly full (`disk_min_free_bytes`) | Only then does the dump upload get HTTP 503 |

All limits are in [deploy/config.example.toml](deploy/config.example.toml).

## Documentation

| Document | Contents |
|---|---|
| [docs/deployment.md](docs/deployment.md) | Containers, systemd, reverse proxy, CLI, backups, metrics |
| [docs/features.md](docs/features.md) | Notices, symbol fetching, carburetor, repeats, bulk delete, raw view, statistics, symbol cache |
| [docs/architecture.md](docs/architecture.md) | Source layout, routes, request flow, database |
| [docs/protocol.md](docs/protocol.md) | The Accelerator client ⇄ server protocol |
| [docs/development.md](docs/development.md) | Tests, the legacy oracle, known limitations |

## Repository layout

| Path | Contents |
|---|---|
| `src/` | The server (ingestion, processing, web, retention, metrics) |
| `templates/`, `static/` | HTML templates and assets |
| `migrations/` | SQLite schema migrations |
| `deploy/` | Example config, container configs, systemd unit |
| `tools/` | Smoke and container tests, packing script, legacy oracle |
| `tests/fixtures/` | Small dumps and symbols, plus golden outputs |
