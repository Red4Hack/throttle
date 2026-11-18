#!/usr/bin/env bash
# Build the image and save it as a gzipped tarball. Deploy by hand (see the end of the output).
# Usage: tools/pack.sh [with|without] [output.tar.gz]
set -euo pipefail
cd "$(dirname "$0")/.."

case ${1:-with} in
  with) TARGET=default ;;
  without) TARGET=without-carburetor ;;
  *) echo "variant must be with|without" >&2; exit 1 ;;
esac
OUT=${2:-throttle.tar.gz}

podman build -t throttle --target "$TARGET" -f Containerfile .
podman save localhost/throttle:latest | gzip > "$OUT"

cat <<MSG

Done: $OUT ($(du -h "$OUT" | cut -f1))

  scp $OUT user@host:~/
  # on the host:
  gunzip -c ~/$OUT | podman load
  podman rm -f throttle
  podman run -d --name throttle -p 127.0.0.1:9090:9090 -v throttle-data:/data \\
    -v ~/throttle.toml:/etc/throttle/throttle.toml:ro \\
    --read-only --tmpfs /tmp --cap-drop=all --security-opt=no-new-privileges \\
    --memory=1g --pids-limit=200 localhost/throttle
MSG
