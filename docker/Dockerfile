FROM quay.io/redsift/ingraind-build:latest AS build
ARG KERNEL_SOURCE=/build/kernel/

ADD . /build/
RUN cargo build --target=x86_64-unknown-linux-musl --release

FROM jess/osquery

USER root

COPY --from=build /build/target/x86_64-unknown-linux-musl/release/ingraind /ingraind
ENTRYPOINT ["/ingraind", "/config/ingraind.toml"]
