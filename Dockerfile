FROM ubuntu:20.04

USER root
ARG BINARY_PATH=./target/x86_64-unknown-linux-musl/release/ingraind
COPY ${BINARY_PATH} /ingraind
ENTRYPOINT ["/ingraind", "/config/ingraind.toml"]
