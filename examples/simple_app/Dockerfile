# Build context is the repository root (see docker-compose.yml):
#   docker build -f examples/simple_app/Dockerfile .
#
# The engine (guard-core-rs) is a sibling path dependency of the adapter, so
# the build needs its source too. It is provided through the additional build
# context named "engine" (compose additional_contexts / docker
# --build-context engine=<path to guard-core-rs checkout>); only the engine
# crate and its workspace manifest are copied out of that context.
FROM rust:1.95-slim-bookworm AS build

WORKDIR /build

COPY --from=engine /Cargo.toml ./guard-core-rs/Cargo.toml
COPY --from=engine /Cargo.lock ./guard-core-rs/Cargo.lock
COPY --from=engine /crates/guard-core-engine ./guard-core-rs/crates/guard-core-engine
COPY --from=engine /crates/guard-core-rs ./guard-core-rs/crates/guard-core-rs

COPY Cargo.toml Cargo.lock ./rocket-guard-rs/
COPY src ./rocket-guard-rs/src
COPY examples ./rocket-guard-rs/examples

WORKDIR /build/rocket-guard-rs
RUN cargo build --release -p rocket-guard-simple-app

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --uid 10001 guard

COPY --from=build /build/rocket-guard-rs/target/release/rocket-guard-simple-app /usr/local/bin/simple-app

USER guard

EXPOSE 8080

ENV ROCKET_ADDRESS=0.0.0.0 \
    ROCKET_PORT=8080

ENTRYPOINT ["/usr/local/bin/simple-app"]
