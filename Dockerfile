FROM jess/osquery

USER root
ARG BINARY_PATH=./target/x86_64-unknown-linux-musl/release/ingraind
RUN ln -sf /usr/bin/osqueryd /usr/bin/osqueryi
COPY ${BINARY_PATH} /ingraind
ENTRYPOINT ["/ingraind", "/config/ingraind.toml"]
