# Throttle

A self-hosted crash report server for the SourceMod [Accelerator](https://github.com/asherkin/accelerator) extension. A single Rust binary backed by SQLite: no PHP, MySQL, Redis or cron.

This is a rewrite of [asherkin/throttle](https://github.com/asherkin/throttle). The old code is still reachable through the `php-final` tag.

## What it does

- Receives dumps and symbols from Accelerator (`POST /submit`, `POST /symbols/submit`), compatible with the client protocol. See `docs/protocol.md`.
- Processes dumps in parallel with [rust-minidump](https://github.com/rust-minidump/rust-minidump), with no external binaries.
- Crash pages (with the `Sys_Error` message and notices), dashboard, Steam login and sharing between users.
- Public statistics page (`/stats`), like the old site: counters, crashes per hour and per day, Top Crashers (Day/Week/Month/All) with drill-down by module, function and stack, latest crashes and processing performance. Charts are SVG rendered on the server.
- Notices: banners attached to crashes by declarative rules.
- Download of missing symbols from HTTP servers in the Breakpad layout (optional).
- **View Raw** with `carburetor` (optional), like the old site: Stack (threads, registers, disassembly, stack memory), Memory and Raw tabs, plus SourcePawn plugin frames.
- Batched retention, disk quota with eviction, Prometheus metrics (optional).

## Why it does not fail with "capacity reached"

The old public server answered `N|...|Sorry, crash submission is currently disabled (capacity reached)` when it filled up. The client **does not retry and deletes the local dump** on any refusal, so every refusal loses the crash forever. Here:

| Situation | What happens |
|---|---|
| Large queue or very common crash (`queue_watermark`, `dedupe_threshold`) | The presubmit answers `M`: only the metadata is uploaded |
| The same crash again (`repeat_window_days`) | The presubmit answers `M` and the upload is counted on the existing crash, without storing another dump (see "Repeats") |
| Per owner+IP limit exceeded (`rate_limit`) | `N` response with a message |
| Disk above quota (`disk_quota_bytes`) | Retention deletes the oldest, never-viewed crashes first |
| Disk nearly full (`disk_min_free_bytes`) | Only then does the dump upload get HTTP 503 |

All limits are in `deploy/config.example.toml`.

## Running

```sh
cargo build --release
cp deploy/config.example.toml throttle.toml   # edit https (and hostname, in production); steam_api_key is optional
./target/release/throttle serve
```

Without `--config`, it reads `throttle.toml` if present and otherwise uses the defaults (`127.0.0.1:8080`, data in `./data`); a `--config` (or `THROTTLE_CONFIG`) that points to a missing file is an error. To accept connections from other machines, use `listen = "0.0.0.0:8080"`. Without `hostname` in the config, the Steam login and the anti-CSRF check use the address you opened the site with (`localhost`, `0.0.0.0`, the LAN IP); in production, set `hostname`. All data (database, dumps, symbols and `secret.key`) lives in `data_dir`.

Container (tested with `podman`, see `tools/container-test.sh`):

```sh
# default image: includes carburetor (deep analysis page)
podman build -t throttle -f Containerfile .
# without carburetor, smaller; dump processing is the same
podman build -t throttle --target without-carburetor -f Containerfile .

podman run -p 9090:9090 -v throttle-data:/data throttle
```

The image runs as the `throttle` user (uid 10001). A named volume works as is; for a host directory use `:U` (`-v ./data:/data:U`), otherwise the server cannot write and warns with that hint. `podman stop` exits immediately (the server handles `SIGTERM`).

Processing (`rust-minidump`) reads 32-bit and 64-bit dumps from Windows, Linux and macOS, with or without carburetor. Carburetor only feeds the `/{id}/carburetor` page (View Raw).

`tools/container-test.sh [with|without|both]` builds the images, starts them with a volume, sends dumps through the real protocol, checks the pages, stops, and starts again. Real server dumps contain passwords and paths, so they do not go into git: put them in `tests/local/*.dmp` (ignored) and both that script and `cargo test` will use them.

There is also `deploy/throttle.service` for systemd, with hardening.

### Pointing the game servers at it

In `addons/sourcemod/configs/core.cfg`:

```
"MinidumpUrl"        "https://throttle.example.com/submit"
"MinidumpSymbolUrl"  "https://throttle.example.com/symbols/submit"
"MinidumpAccount"    "YOUR_STEAMID64"
```

Do not set `MinidumpBinaryUrl`: this server never asks for binaries.

### Behind a reverse proxy

Set `https = true`, set `hostname = "throttle.example.com"` (the public address; the `Host` the proxy forwards may differ) and list the proxy in `trusted_proxies`. Only a listed proxy can set `X-Forwarded-For`. The proxy's upload limit (`client_max_body_size` in nginx) must be larger than `limits.max_dump_bytes`.

## Optional features

### Notices

Rules are data, never SQL. Each `[[notices]]` in the config has an `id`, a `severity` (`info`, `warning`, `danger`), a `text` and a `[notices.rule]` in which **all** the present conditions must hold: `frame` (module and/or function within the first `within` frames of the crashed thread), `metadata`, `cmdline`, `module_loaded`, `module_missing`. Patterns use `*` and `?`. Notices are synced to the database at startup and applied when a crash is processed (or reprocessed).

A notice whose id starts with `nosteam-` has an extra effect: the owner+IP that received it is refused for 30 days, with the usual protocol message.

### Symbols from HTTP servers

`[symbol_fetch]` lists servers in the `<url>/<name>/<build id>/<stem>.sym` layout (Mozilla's follows this layout). Every `interval_secs`, the `*.pdb` modules of processed crashes that still lack symbols are downloaded, and those crashes are reprocessed. Each server's `store` must be in `processing.symbol_stores`; put the stores you trust before `public`.

Downloading symbols from the **Microsoft Symbol Server is not supported**: it serves PDBs, not `.sym`, and the conversion would need `dump_syms`.

### Deep analysis (carburetor)

[carburetor](https://github.com/asherkin/carburetor) is a C++ program that parses the dump with Breakpad and adds registers, SourcePawn plugin frames, stack memory and disassembly. Set `[carburetor] path` (an absolute path) and the **View Raw** button on the crash page opens `/{id}/carburetor` for whoever can manage the crash, with the three tabs of the old site: **Stack** (crash reason, each thread with frames, registers, disassembly around the instruction and the stack memory in hex, plus "Found via…"), **Memory** (hex of all regions) and **Raw** (the JSON). The old site did this with JavaScript in the browser; here everything is assembled on the server, and the tabs are CSS only, because the site's CSP does not allow scripts. Each tab shows at most 8 MiB; `/{id}/carburetor/data` returns the full JSON.

Since it parses untrusted dumps, it runs without a shell, with an empty environment, time and output limits, and at most `max_concurrent` runs at the same time. Without `path` the feature does not exist (the pages answer 404).

To build it: `cmake -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -S carburetor -B build && make -C build` (needs `cmake`, `g++`, `git` and `zlib`; the build downloads Breakpad and other unpinned dependencies), or use the default `Containerfile` image, which already includes it.

## Repeats, bulk delete and raw view

**Repeats.** A plugin that crashes every round, or a new SourceMod that brings the server down several times, no longer fills the account with identical dumps. Two crashes are the same when they have the same owner (anonymous: the same address) and the same presubmit fingerprint (crash reason plus module, build id and offset of the first frames; addresses outside any module change on every run because of ASLR and are left out when there are at least two frames in modules). Within `limits.repeat_window_days` (30 by default, `0` disables), the presubmit answers `M`, and the upload creates no row and stores no dump: it increments `repeats` and updates `last_repeat_at` on the existing crash, and answers with that crash's ID, so a plugin that asks for the uploaded crash gets a real ID. The fingerprint comes from the signed presubmit token, so it cannot be forged with an upload alone. The window slides: while the crash keeps repeating, it does not expire through retention. The dashboard shows `×N`, the crash page says how many times it came back, and the statistics add up the repeats. A repeat does not count toward `rate_limit`, because it creates no row.

**Bulk delete.** On the dashboard, each report has a checkbox; "Select page" marks all on the page and "Clear" unmarks them. Marked rows are highlighted, and a fixed bar at the bottom of the screen shows how many are marked and has "Delete selected", which asks for confirmation (with Cancel). It is all JavaScript-free. Permission is all or nothing: if one of the marked crashes is not yours (nor shared with you, nor are you an admin), nothing is deleted. Ids that no longer exist are ignored. The maximum is 200 per request.

**Even More Raw.** `/{id}/raw`, for whoever manages the crash, shows the whole dump as text: reason, system, the stack of every thread and the modules, like `minidump_stackwalk`. It does not need carburetor, and it is what the View Raw button opens when carburetor is not configured. It does not print process memory (command line, environment). Only two reads at a time, 30 s at most and 8 MiB of output.

**Statistics.** `/stats` follows the old page, with the rewrite's style. Clicking a Top Crashers row opens `/stats/{module}/{function}`; the "N reports share this crash signature" alert on the crash page opens `/stats/{stack hash}`. The charts across the site come from the hourly counters (the old site used RRD files), so they keep history after retention deletes crashes and count repeats; the filtered charts only see crashes that still exist. Munin's `.png` files became four charts (processed, average time, failures and refused per hour). "Unique servers" counts distinct servers by `ServerID` (or by command line). As in the old site, the "Latest Crash Reports" list shows crash IDs and the top function, with no owner or address, and the Top Crashers default is All.

## Operation

```sh
throttle check-config            # validates the configuration (secrets hidden)
throttle clean                   # one retention pass now
throttle backup /bk/throttle.sqlite   # consistent copy of the database while the server runs
```

Dumps and symbols are plain files in `data_dir`: copy them with rsync.

`GET /metrics` is off until you set `metrics_token` (minimum 16 characters) and use `Authorization: Bearer <token>`. `GET /healthz` checks the database.

**Symbol cache.** Parsed `.sym` files are kept in memory, shared by all workers (`processing.symbol_cache_mib`, 256 MiB by default, 0 disables). In a test with a synthetic 28 MiB `.sym`, re-reading cost about 280 ms and copying the already parsed file about 43 ms; the parsed file takes 3.5 to 5.7 times the size of the text, so the limit is a memory estimate (LRU), not a file count. The real peak can exceed the budget for a moment, because of the files being loaded or copied at that time. A file replaced on disk counts as another entry (the key includes size and date), and modules without symbols never enter the cache, so a symbol uploaded later is always seen. `/metrics` shows `throttle_symbol_cache_{bytes,hits_total,misses_total}`.

## Development

```sh
cargo test
cargo clippy --all-targets
cargo build --release && tools/smoke.sh   # end-to-end test with the real binary
THROTTLE_TEST_CARBURETOR=/path/to/carburetor cargo test the_real_program   # optional
```

The tests include an oracle: `tools/oracle/fetch.sh` extracts the legacy `minidump_stackwalk` from the `php-final` tag and `tools/oracle/golden.sh` regenerates the expected outputs in `tests/fixtures/golden`. The `process::tests::analysis_matches_the_legacy_minidump_stackwalk` test compares the rewrite against them. The only accepted differences are documented in the test itself.

## Known limitations

What was **not** done or not verified:

- **Importing data from the old PHP server.** The old repository had no data and there is no MySQL database here to test an import against, so I did not write one. The new server starts empty.
- **Microsoft Symbol Server** (see above).
- **The carburetor viewer** lacks the old JavaScript's interactivity (the site's CSP does not allow scripts): the Stack, Memory and Raw tabs are server-built text, cut at 8 MiB per tab. The full JSON is at `/{id}/carburetor/data`.
- **Inline frames.** `INLINE` records in `.sym` files are understood by `rust-minidump` (`StackFrame::inlines`), but the page shows only the outer function of each frame, as the PHP did, and the stack hash also ignores inlines.
- **Stack hash.** The hash of crashes with *stack scan*-only stacks (no symbols/CFI) is not equal to the PHP's, because the old Breakpad scan generated frames without a module that `rust-minidump` discards. It would only matter if you imported old data.
- **`Sys_Error`.** Message extraction is the legacy heuristic (a register pointing inside the frame). It was tested with synthetic x86 and amd64 dumps, never with a real engine crash.
- **Jump to an address that is not code** (call through an invalid function pointer, common in plugins). EIP/RIP ends up outside any module and the original Breakpad followed the frame pointer into garbage. Here, if the word at `[esp]` points into a loaded module, the stack is unwound from that return address, and the page says so. Frames after the first real one still depend on symbols (CFI): without them, they may be garbage, as with any stack walker.
- **"Symbols missing".** Resending a `.dmp` with `curl` does not carry the symbols along: the `.sym` files for Linux modules are generated by the game server's Accelerator, which uploads the ones the presubmit asks for (`Y`). For that, `MinidumpUrl` and `MinidumpSymbolUrl` in `core.cfg` must point at this server, not at `crash.limetech.org`. When the symbols arrive, the crashes are processed again.
- **The `unsupported CPU architecture` warning** came from `minidump-processor`, which only analyzes the crashing instruction on amd64. It does not affect the result and is now silenced by default (`RUST_LOG=minidump_processor=warn` brings it back). Crashes processed before migration `0002` have no reason/address stored until they are reprocessed (admin *Reprocess* button).
- **Not tested for real:** the actual Accelerator client and the actual Steam login.
