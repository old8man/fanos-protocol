# FANOS node — reproducible multi-stage container image (spec §11, #120).
#
# Build:  docker build -t fanos-node .
# Run:    docker run -d --name fanos \
#           -p 9000:9000/udp \
#           -v fanos-state:/var/lib/fanos \
#           -v "$PWD/deploy/node.conf.example:/etc/fanos/node.conf:ro" \
#           fanos-node
#
# The QUIC transport is UDP, so the port MUST be published as udp. The node's self-certifying
# identity (and therefore its overlay coordinate) persists in the /var/lib/fanos volume — keep that
# volume across restarts/upgrades to keep the same coordinate.
# syntax=docker/dockerfile:1

# ---- build stage ---------------------------------------------------------------------------------
# The `rust` image ships rustup; the exact nightly + components come from rust/rust-toolchain.toml,
# which rustup installs automatically on the first cargo invocation — so the image toolchain is
# pinned by the repo, not by the base tag.
FROM rust:1-bookworm AS build
WORKDIR /src
COPY rust/ ./rust/
WORKDIR /src/rust
# Cache the registry and target dir across builds; copy the release binary OUT of the cached target
# in the same layer (a cache mount does not persist past the RUN).
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/rust/target \
    cargo build --release -p fanos-node --bin fanos \
 && cp target/release/fanos /usr/local/bin/fanos

# ---- runtime stage -------------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime
# A dedicated unprivileged user; the state directory holds the persistent identity.
RUN groupadd --system fanos \
 && useradd --system --gid fanos --home-dir /var/lib/fanos --shell /usr/sbin/nologin fanos \
 && mkdir -p /var/lib/fanos /etc/fanos \
 && chown -R fanos:fanos /var/lib/fanos
COPY --from=build /usr/local/bin/fanos /usr/local/bin/fanos
EXPOSE 9000/udp
VOLUME ["/var/lib/fanos"]
USER fanos
ENTRYPOINT ["/usr/local/bin/fanos"]
# Default command: run a node from the mounted config. Override to run `fanos id`, `fanos resolve`, …
CMD ["node", "--config", "/etc/fanos/node.conf"]
