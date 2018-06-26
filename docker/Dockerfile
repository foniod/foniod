FROM ingraind-build AS build

ARG KERNEL_SOURCE=/build/kernel/

ADD . /build/
RUN cargo build --release

FROM debian:stable

COPY --from=build /usr/lib/libbpf.so.* /usr/lib/
COPY --from=build /build/target/release/ingraind /bin

CMD /bin/ingraind
