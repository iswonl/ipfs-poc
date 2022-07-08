# Build Stage
FROM rustlang/rust:nightly-slim AS builder
USER 0:0
WORKDIR /home/rust/src

RUN USER=root cargo new --bin backend
WORKDIR /home/rust/src/backend
COPY Cargo.toml Cargo.lock ./
RUN apt-get update && apt-get install -y libssl-dev pkg-config

COPY src ./src
RUN cargo install --locked --path .

# Bundle Stage
FROM debian:buster-slim
RUN apt-get update && apt-get install -y ca-certificates
COPY --from=builder /usr/local/cargo/bin/backend ./
EXPOSE 8000
ENV BACKEND_HOST 0.0.0.0
ENV BACKEND_PORT 8000
CMD ["./backend"]