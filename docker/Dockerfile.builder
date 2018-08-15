FROM ubuntu:18.04

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN apt-get update \
    && apt-get -y install debhelper cmake libllvm6.0 llvm-6.0-dev libclang-6.0-dev \
       libelf-dev bison flex libedit-dev clang-format-6.0 python python-netaddr \
       python-pyroute2 luajit libluajit-5.1-dev arping iperf netperf ethtool \
       devscripts zlib1g-dev libfl-dev \
       pkg-config libssl-dev \
       curl \
       git \
       clang \
       musl musl-tools musl-dev 

RUN curl https://sh.rustup.rs -sSf > rustup.sh \
    && sh rustup.sh -y \
          --default-toolchain nightly \
          --no-modify-path \
    && rustup target add x86_64-unknown-linux-musl \
    && rustup --version \
    && cargo --version \
    && rustc --version

RUN ln -s /usr/bin/llc-6.0 /usr/bin/llc 

WORKDIR /tmp
RUN git clone https://github.com/iovisor/bcc.git \
    && cd bcc; mkdir build; cd build \
    && cmake -DCMAKE_INSTALL_PREFIX=/usr .. \
    && make \
    && make install

RUN cargo install bindgen

WORKDIR /build
