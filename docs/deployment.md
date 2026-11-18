# Deployment and operation

## Configuration

Copy [`deploy/config.example.toml`](../deploy/config.example.toml); every key is optional and the values in it are the defaults. Check a config with:

```sh
throttle --config throttle.toml check-config   # prints the resolved config, secrets hidden
```

Key settings:

| Key | Notes |
|---|---|
| `listen` | Default `127.0.0.1:8080`. Use `0.0.0.0:8080` to accept connections from other machines. |
| `hostname` | Public host name. Without it, the Steam login and the anti-CSRF check use the address the browser connected to (`localhost`, `0.0.0.0`, the LAN IP). **Set it in production.** |
| `https` | `true` when the site is reached over HTTPS, directly or behind a TLS proxy. |
| `data_dir` | Database, dumps, symbols and `secret.key` all live here. |
| `trusted_proxies` | Reverse proxies allowed to set `X-Forwarded-For`. |
| `steam_api_key` | Optional. The Steam login works without it. |
| `metrics_token` | Enables `GET /metrics` (minimum 16 characters). |
| `admins`, `developers` | Lists of SteamID64. |

## Containers

Tested with `podman`; see `tools/container-test.sh`.

```sh
# default image: includes carburetor (deep analysis page)
podman build -t throttle -f Containerfile .
# without carburetor, smaller; dump processing is the same
podman build -t throttle --target without-carburetor -f Containerfile .
# carburetor pinned to a commit
podman build -t throttle --build-arg CARBURETOR_REF=<commit> -f Containerfile .

podman run -p 9090:9090 -v throttle-data:/data throttle
```

- The image runs as the `throttle` user (uid 10001).
- A named volume works as is. For a host directory use `:U` (`-v ./data:/data:U`), otherwise the server cannot write and warns with that hint.
- `podman stop` exits immediately (the server handles `SIGTERM`).
- Mount your own config over `/etc/throttle/throttle.toml`. The defaults are in `deploy/config.container.toml` and `deploy/config.container-carburetor.toml`.

### Packing for a remote host

```sh
tools/pack.sh [with|without] [output.tar.gz]
```

Builds the image and saves it as a gzipped tarball. The end of its output shows the `scp`, `podman load` and `podman run` commands for the remote host, including a locked-down run (`--read-only`, `--cap-drop=all`, memory and pids limits).

## systemd

`deploy/throttle.service` runs the binary as the `throttle` user with `StateDirectory=throttle` (set `data_dir = "/var/lib/throttle"` in the config) and a hardened sandbox (`ProtectSystem=strict`, `NoNewPrivileges`, `MemoryDenyWriteExecute`, and more).

## Behind a reverse proxy

Set `https = true`, set `hostname = "throttle.example.com"` (the public address; the `Host` the proxy forwards may differ) and list the proxy in `trusted_proxies`. Only a listed proxy can set `X-Forwarded-For`. The proxy's upload limit (`client_max_body_size` in nginx) must be larger than `limits.max_dump_bytes`.

## Command line

```sh
throttle serve                        # run the web server
throttle check-config                 # validate the configuration (secrets hidden)
throttle clean                        # one retention pass now
throttle backup /bk/throttle.sqlite   # consistent copy of the database while the server runs
```

`--config` (or `THROTTLE_CONFIG`) works with every command.

## Backups

`throttle backup` copies the database consistently while the server is running. Dumps and symbols are plain files in `data_dir`: copy them with rsync.

## Retention and disk

Retention runs every `retention.interval_secs` in batches. It applies `max_age_days`, `keep_per_owner` and `keep_per_anonymous_ip`, and evicts the oldest, never-viewed dumps when `limits.disk_quota_bytes` is exceeded. Crashes that keep repeating do not expire (see [Repeats](features.md#repeats)). The server answers 503 to a dump upload only when free disk falls below `limits.disk_min_free_bytes`.

## Monitoring

- `GET /healthz` checks the database.
- `GET /metrics` is off until `metrics_token` is set; use `Authorization: Bearer <token>`. It includes `throttle_symbol_cache_{bytes,hits_total,misses_total}`.
- Logging uses `RUST_LOG`. The default is `info,minidump_processor=error`, because `minidump-processor` warns about every x86 dump (`unsupported CPU architecture`). Use `RUST_LOG=minidump_processor=warn` to bring those back.
