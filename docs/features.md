# Features

## Repeats

A plugin that crashes every round, or a new SourceMod that brings the server down several times, no longer fills the account with identical dumps.

- Two crashes are the same when they have the same owner (anonymous: the same address) and the same presubmit fingerprint: crash reason plus module, build id and offset of the first frames. Addresses outside any module change on every run because of ASLR, so they are left out when there are at least two frames in modules.
- Within `limits.repeat_window_days` (30 by default, `0` disables), the presubmit answers `M`, and the upload creates no row and stores no dump. It increments `repeats` and updates `last_repeat_at` on the existing crash, and answers with that crash's ID, so a plugin that asks for the uploaded crash gets a real ID.
- The fingerprint comes from the signed presubmit token, so it cannot be forged with an upload alone.
- The window slides: while the crash keeps repeating, it does not expire through retention.
- The dashboard shows `×N`, the crash page says how many times it came back, and the statistics add up the repeats.
- A repeat does not count toward `rate_limit`, because it creates no row.

## Dashboard and bulk delete

Each report has a checkbox. "Select page" marks all on the page and "Clear" unmarks them. Marked rows are highlighted, and a fixed bar at the bottom shows how many are marked and has "Delete selected", which asks for confirmation (with Cancel). It is all JavaScript-free.

Permission is all or nothing: if one of the marked crashes is not yours (nor shared with you, nor are you an admin), nothing is deleted. Ids that no longer exist are ignored. The maximum is 200 per request.

## Statistics

`/stats` follows the old page, with the rewrite's style.

- Clicking a Top Crashers row opens `/stats/{module}/{function}`; the "N reports share this crash signature" alert on the crash page opens `/stats/{stack hash}`.
- The charts across the site come from hourly counters (the old site used RRD files), so they keep history after retention deletes crashes and they count repeats. Charts filtered by module or function only see crashes that still exist.
- Munin's `.png` files became four charts: processed, average time, failures and refused per hour.
- "Unique servers" counts distinct servers by `ServerID` (or by command line).
- As in the old site, "Latest Crash Reports" shows crash IDs and the top function, with no owner or address, and the Top Crashers default is All.

## Raw view

`/{id}/raw`, for whoever manages the crash, shows the whole dump as text: reason, system, the stack of every thread and the modules, like `minidump_stackwalk`. It does not need carburetor, and it is what the View Raw button opens when carburetor is not configured. It does not print process memory (command line, environment). Only two reads at a time, 30 s at most and 8 MiB of output.

## Deep analysis (carburetor)

[carburetor](https://github.com/asherkin/carburetor) is a C++ program that parses the dump with Breakpad and adds registers, SourcePawn plugin frames, stack memory and disassembly.

Set `[carburetor] path` (an absolute path) and the **View Raw** button on the crash page opens `/{id}/carburetor` for whoever can manage the crash. It has the three tabs of the old site:

- **Stack**: crash reason, each thread with frames, registers, disassembly around the instruction and the stack memory in hex, plus "Found via…".
- **Memory**: hex of all regions.
- **Raw**: the JSON.

The old site did this with JavaScript in the browser; here everything is assembled on the server, and the tabs are CSS only, because the site's CSP does not allow scripts. Each tab shows at most 8 MiB; `/{id}/carburetor/data` returns the full JSON.

Since it parses untrusted dumps, it runs without a shell, with an empty environment, time and output limits, and at most `max_concurrent` runs at the same time. Without `path` the feature does not exist (the pages answer 404).

To build it: `cmake -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -S carburetor -B build && make -C build` (needs `cmake`, `g++`, `git` and `zlib`; the build downloads Breakpad and other unpinned dependencies), or use the default `Containerfile` image, which already includes it.

## Notices

Rules are data, never SQL. Each `[[notices]]` in the config has an `id`, a `severity` (`info`, `warning`, `danger`), a `text` and a `[notices.rule]` in which **all** the present conditions must hold:

- `frame`: module and/or function within the first `within` frames of the crashed thread
- `metadata`
- `cmdline`
- `module_loaded`, `module_missing`

Patterns use `*` and `?`. Frame modules, `module_loaded` and `module_missing` ignore case; functions, metadata values and the command line do not. Notices are synced to the database at startup and applied when a crash is processed (or reprocessed).

A notice whose id starts with `nosteam-` has an extra effect: the owner+IP that received it is refused for 30 days, with the usual protocol message.

```toml
[[notices]]
id = "sys-error"
severity = "info"
text = "The engine aborted with an error message (Sys_Error)."
[notices.rule]
frame = { module = "engine*.so", function = "Sys_Error*", within = 3 }
```

## Symbols from HTTP servers

`[symbol_fetch]` lists servers in the `<url>/<name>/<build id>/<stem>.sym` layout (Mozilla's follows this layout). Every `interval_secs`, the `*.pdb` modules of processed crashes that still lack symbols are downloaded, and those crashes are reprocessed. A module that no server has is asked for again after `retry_days`.

Each server's `store` must be in `processing.symbol_stores`; put the stores you trust before `public`, because anything anyone uploads lands in `public`.

Downloading symbols from the **Microsoft Symbol Server is not supported**: it serves PDBs, not `.sym`, and the conversion would need `dump_syms`.

## Symbol cache

Parsed `.sym` files are kept in memory, shared by all workers (`processing.symbol_cache_mib`, 256 MiB by default, 0 disables).

- In a test with a synthetic 28 MiB `.sym`, re-reading cost about 280 ms and copying the already parsed file about 43 ms.
- The parsed file takes 3.5 to 5.7 times the size of the text, so the limit is a memory estimate (LRU), not a file count.
- The real peak can exceed the budget for a moment, because of the files being loaded or copied at that time.
- A file replaced on disk counts as another entry (the key includes size and date), and modules without symbols never enter the cache, so a symbol uploaded later is always seen.
