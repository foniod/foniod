FROM scratch

ARG BINARY_PATH=./target/x86_64-unknown-linux-musl/release/ingraind
COPY ${BINARY_PATH} /ingraind
CMD ["/ingraind", "/config/ingraind.toml"]
