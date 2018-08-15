FROM ingraind-build AS build

ARG KERNEL_SOURCE=/build/kernel/

ADD . /build/
RUN cargo build --target=x86_64-unknown-linux-musl --release

FROM scratch

COPY --from=build /build/target/x86_64-unknown-linux-musl/release/ingraind /ingraind
CMD ["/ingraind"]
