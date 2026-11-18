# Architecture

One Rust binary: an [axum](https://github.com/tokio-rs/axum) web server, a SQLite database, and background tasks (dump processing, retention, symbol fetching) in the same process.

## Request flow

```text
Accelerator ── POST /submit (presubmit) ──▶ ingest: signature, token, limits ──▶ Y / M / N
            ── POST /submit (upload)    ──▶ ingest: validate, store dump + metadata, enqueue
            ── POST /symbols/submit     ──▶ ingest: validate, store .sym.gz

queue ──▶ process workers: rust-minidump + symbols (cache, HTTP fetch) ──▶ stack hash, notices, Sys_Error
                                                                      └─▶ database

browser ──▶ web: dashboard, crash pages, stats, share, Steam login
retention / symfetch / metrics: periodic tasks and /metrics
```

The queue is explicit (a database table), so dumps are analyzed off the request path and a burst of uploads does not block ingestion.

## Source layout

| Path | Role |
|---|---|
| `src/main.rs` | CLI (`serve`, `check-config`, `clean`, `backup`) |
| `src/app.rs` | Shared state, router, `/healthz`, server startup |
| `src/config.rs` | TOML configuration and validation |
| `src/db.rs`, `migrations/` | SQLite access and schema migrations |
| `src/ids.rs` | Crash IDs (12-char base32) and the UUID mapping |
| `src/ingest/` | Accelerator protocol: presubmit, upload, symbols, signed token, client IP, metadata parsing, storage |
| `src/process/` | Dump analysis: `rust-minidump`, symbol supplier and cache, `Sys_Error` extraction, repo links, rendering |
| `src/web/` | Pages: dashboard, crash details, raw and deep analysis, statistics, sharing, profiles, Steam login, sessions |
| `src/notice.rs` | Declarative notice rules |
| `src/retention.rs` | Age, per-owner and disk-quota cleanup |
| `src/symfetch.rs` | Background symbol download from HTTP servers |
| `src/carburetor.rs` | Sandboxed runs of the external carburetor program |
| `src/metrics.rs`, `src/stats.rs` | Prometheus metrics and hourly counters |
| `templates/`, `static/` | HTML templates and assets (CSS, theme toggle, favicon) |

## Routes

| Route | Purpose |
|---|---|
| `POST /submit` | Presubmit and dump upload |
| `POST /symbols/submit` | Symbol upload |
| `GET /healthz`, `GET /metrics` | Health check; Prometheus metrics (token required) |
| `GET /` , `/robots.txt`, `/static/*`, `/favicon.ico` | Landing page and assets |
| `GET /login`, `/login/callback`, `POST /logout` | Steam login |
| `GET /dashboard`, `POST /dashboard/delete` | Crash list and bulk delete |
| `GET /stats`, `/stats/{module}`, `/stats/{module}/{function}` | Public statistics |
| `/settings/share`, `/settings/share/{invite,accept,revoke}` | Sharing crashes between users |
| `GET /{id}` | Crash details |
| `GET /{id}/download`, `/metadata`, `/console`, `/raw` | Dump, metadata file, console history, raw text view |
| `POST /{id}/delete`, `/{id}/reprocess` | Delete or reprocess a crash |
| `GET /{id}/carburetor`, `/{id}/carburetor/data` | Deep analysis page and its JSON |

The ingest routes are registered before `/{id}`, so they win over crash IDs.

## Database

SQLite, with migrations in `migrations/`:

| Migration | Adds |
|---|---|
| `0001_init.sql` | Base schema |
| `0002_crash_reason.sql` | Crash reason and address |
| `0003_repeats.sql` | Repeat counters |

Dumps, symbols and `secret.key` are plain files under `data_dir`. The presubmit token is an HMAC with the server secret (not `md5` as in the legacy server).

## Security notes

- Dumps and symbols are untrusted: sizes are capped (`limits.*`), symbol names and ids are validated, and carburetor runs sandboxed.
- The site's CSP forbids inline scripts, so the UI works without JavaScript beyond the small theme toggle.
- `/submit` has a cheap per-IP cap (120 requests per minute, in memory) because presubmits cost database work but add no crash row. The client then uploads anyway, so nothing is lost.
- Command lines are shown with `+sv_password`, `+rcon_password` and `+sv_setsteamaccount` values masked.
