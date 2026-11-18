# Default image (includes carburetor, which feeds the deep analysis page):
#   podman build -t throttle -f Containerfile .
# Without carburetor (smaller; dump processing is the same, just no deep analysis):
#   podman build -t throttle --target without-carburetor -f Containerfile .
# With carburetor pinned to a commit:
#   podman build -t throttle --build-arg CARBURETOR_REF=<commit> -f Containerfile .

FROM docker.io/library/rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY migrations migrations
COPY templates templates
COPY static static
COPY src src
RUN cargo build --release --locked

# The carburetor build pulls in Breakpad, nlohmann/json, cppcodec and distorm
# without pinned versions; CARBURETOR_REF pins only carburetor itself.
FROM docker.io/library/debian:bookworm-slim AS carburetor-build
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential cmake git ca-certificates zlib1g-dev \
 && rm -rf /var/lib/apt/lists/*
ARG CARBURETOR_REF=master
RUN git clone https://github.com/asherkin/carburetor /src \
 && git -C /src checkout "$CARBURETOR_REF"
RUN cmake -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -S /src -B /build \
 && make -C /build -j"$(nproc)"

FROM docker.io/library/debian:bookworm-slim AS runtime-base
# CA certificates: the server talks to Steam over HTTPS.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin throttle \
 && mkdir /data /etc/throttle \
 && chown throttle /data
COPY --from=build /src/target/release/throttle /usr/local/bin/throttle
VOLUME /data
EXPOSE 9090
ENTRYPOINT ["throttle", "--config", "/etc/throttle/throttle.toml"]
CMD ["serve"]

# Without carburetor: rust-minidump already reads 32-bit and 64-bit dumps.
FROM runtime-base AS without-carburetor
COPY deploy/config.container.toml /etc/throttle/throttle.toml
USER throttle

# With carburetor: adds the deep analysis (default, last stage).
FROM runtime-base AS default
RUN apt-get update \
 && apt-get install -y --no-install-recommends libstdc++6 zlib1g \
 && rm -rf /var/lib/apt/lists/*
COPY --from=carburetor-build /build/carburetor /usr/local/bin/carburetor
COPY deploy/config.container-carburetor.toml /etc/throttle/throttle.toml
USER throttle
