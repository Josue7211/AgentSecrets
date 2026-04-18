FROM rust:1.88-bookworm AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --create-home --home-dir /app appuser
RUN mkdir -p /var/lib/secret-broker && chown appuser:appuser /var/lib/secret-broker
WORKDIR /app
COPY --from=builder /app/target/release/secret-broker /usr/local/bin/secret-broker
USER appuser

ENV SECRET_BROKER_BIND=0.0.0.0:4815
EXPOSE 4815

CMD ["secret-broker"]
