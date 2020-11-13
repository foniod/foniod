FROM ubuntu:20.04

USER root
ARG BINARY_PATH=./target/x86_64-unknown-linux-musl/release/ingraind
RUN apt update && apt -y install ca-certificates && apt clean
COPY ${BINARY_PATH} /ingraind
ENTRYPOINT ["/ingraind", "/config/ingraind.toml"]
