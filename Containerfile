# hecate-sentinel — L2 hecate-om service: the federated mesh commons for
# warden report correlation. Outbound macula client (dials a station seed),
# owns a reckon-db store. 
# Pushed to ghcr.io/hecate-services/hecate-sentinel:latest + :semver.
#
# Multi-stage: the builder compiles the macula_quic NIF FROM SOURCE
# (MACULA_FORCE_SOURCE_BUILD=1) so we always get the 5.1.0 connect-hang fix,
# never a fetched precompiled artifact. Runtime is a bare Alpine (same 3.22 as
# erlang:27-alpine) with the release's bundled ERTS.

#----------------------------------------------------------------------
# Stage 1 — builder: Erlang + Rust + rebar3 + deps + release
#----------------------------------------------------------------------
FROM docker.io/erlang:27-alpine AS builder
WORKDIR /build

# Build toolchain. Rust via rustup (Alpine's rustc lags what macula's Rust deps
# need); crt-static off so the NIF links as a cdylib.
RUN apk add --no-cache git curl bash build-base cmake perl linux-headers
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain stable --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}"
ENV RUSTFLAGS="-C target-feature=-crt-static"
ENV MACULA_FORCE_SOURCE_BUILD=1
# rebar3 runs the reckon_db + macula NIF build hooks in a subprocess whose PATH
# does NOT include /root/.cargo/bin, so symlink the toolchain into /usr/local/bin
# (always on the default PATH any subprocess inherits). rustup's proxies dispatch
# on argv[0], so the symlinks resolve cargo/rustc correctly.
RUN ln -sf /root/.cargo/bin/rustup /usr/local/bin/cargo \
    && ln -sf /root/.cargo/bin/rustup /usr/local/bin/rustc \
    && ln -sf /root/.cargo/bin/rustup /usr/local/bin/rustup \
    && cargo --version && rustc --version

RUN curl -fsSL https://s3.amazonaws.com/rebar3/rebar3 -o /usr/local/bin/rebar3 \
    && chmod +x /usr/local/bin/rebar3

# Deps first (cacheable until rebar.config changes). No rebar.lock committed
# (org convention: lockfiles stay out of git), so deps resolve at build time.
COPY rebar.config ./
RUN rebar3 get-deps

# Source, then the production release (bundles ERTS, strips debug_info).
COPY config ./config
COPY apps ./apps
RUN rebar3 as prod release

#----------------------------------------------------------------------
# Stage 2 — runtime: slim Alpine + the assembled release
#----------------------------------------------------------------------
FROM docker.io/alpine:3.22
RUN apk add --no-cache ncurses-libs libstdc++ libgcc openssl ca-certificates curl
WORKDIR /app
COPY --from=builder /build/_build/prod/rel/hecate_sentinel ./
RUN mkdir -p /data

ENV HOME=/app
# Substitute ${VAR} in vm.args/sys.config from the container env at boot.
ENV RELX_REPLACE_OS_VARS=true
# Defaults; the per-node env file overrides seeds, realm, node host, cookie.
ENV HECATE_DATA_DIR=/data
ENV HECATE_NODE_HOST=127.0.0.1
ENV HECATE_COOKIE=hecate_sentinel
# GeoIP databases are MOUNTED here at runtime (never bundled — MaxMind licence).
ENV HECATE_SENTINEL_GEOIP=/geoip
# Ports and node name are per-NODE, not per-image: under --network host they
# land on the host, so several nodes on one box each need their own. Every
# ${VAR} in sys.config/vm.args must resolve at boot or the term is malformed,
# hence defaults for all three.
ENV HECATE_NODE_NAME=hecate_sentinel
ENV HECATE_HEALTH_PORT=8470
# The capital this node dials. Travels on the public facts, so a spectator can
# say where a mind spoke from.
ENV HECATE_NODE_LOCALE=unknown

# Realm service-principal cert mounts here; station socket under /run/macula.
VOLUME ["/etc/hecate/secrets", "/var/lib/hecate-sentinel"]

# Health + entity ingress (register/send/receive/broadcast/artifact). Defaults;
# a node started on other ports exposes those instead.
ENTRYPOINT ["/app/bin/hecate_sentinel"]
CMD ["foreground"]
