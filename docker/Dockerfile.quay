FROM quay.io/redsift/ingraind-build:latest AS build

ADD . /build/
RUN cargo build --target=x86_64-unknown-linux-musl --release

FROM scratch

COPY --from=build /build/target/x86_64-unknown-linux-musl/release/ingraind /ingraind
CMD ["/ingraind"]
