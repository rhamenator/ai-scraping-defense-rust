FROM rust:1.88-bookworm AS builder

WORKDIR /app
COPY . .
RUN cargo build --release --workspace

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --home-dir /home/appuser --uid 1000 appuser

COPY --from=builder /app/target/release/admin-ui /usr/local/bin/admin-ui
COPY --from=builder /app/target/release/ai-service /usr/local/bin/ai-service
COPY --from=builder /app/target/release/captcha-service /usr/local/bin/captcha-service
COPY --from=builder /app/target/release/cloud-dashboard /usr/local/bin/cloud-dashboard
COPY --from=builder /app/target/release/cloud-proxy /usr/local/bin/cloud-proxy
COPY --from=builder /app/target/release/config-recommender /usr/local/bin/config-recommender
COPY --from=builder /app/target/release/edge-ops /usr/local/bin/edge-ops
COPY --from=builder /app/target/release/escalation-engine /usr/local/bin/escalation-engine
COPY --from=builder /app/target/release/pay-per-crawl /usr/local/bin/pay-per-crawl
COPY --from=builder /app/target/release/prompt-router /usr/local/bin/prompt-router
COPY --from=builder /app/target/release/public-blocklist /usr/local/bin/public-blocklist
COPY --from=builder /app/target/release/rag-trainer /usr/local/bin/rag-trainer
COPY --from=builder /app/target/release/tarpit-api /usr/local/bin/tarpit-api

USER appuser
ENV RUST_LOG=info
