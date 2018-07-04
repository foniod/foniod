FROM ingraind-build AS build

ARG KERNEL_SOURCE=/build/kernel/

ADD . /build/
RUN cargo build --release

FROM ubuntu:18.04

RUN apt update && apt install -y libssl1.1 ca-certificates

COPY --from=build /usr/lib/x86_64-linux-gnu/libbpf.so /usr/lib/
COPY --from=build /usr/lib/x86_64-linux-gnu/libbpf.so.0  /usr/lib/
COPY --from=build /usr/lib/x86_64-linux-gnu/libbpf.so.0.6.0  /usr/lib/
COPY --from=build /build/target/release/ingraind /bin

CMD /bin/ingraind
