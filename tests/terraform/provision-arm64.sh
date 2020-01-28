#!/bin/bash

set -e

apt-get update
apt-get install -y \
    llvm llvm-9 libllvm9 llvm-9-dev clang libclang-9-dev clang-format-9 \
    bison flex debhelper cmake devscripts \
    zlib1g-dev libfl-dev libelf-dev libedit-dev libssl-dev \
    curl git \
    musl musl-tools musl-dev \
    linux-headers-aws \
    capnproto \
    pkg-config

curl --proto '=https' --tlsv1.2 -sSf -o rustup.sh https://sh.rustup.rs
sh rustup.sh -y \
    --default-toolchain stable

. /root/.cargo/env
rustup toolchain install stable --force
rustup target add aarch64-unknown-linux-musl

cd /home/ubuntu/ingraind

sed -i 's/eth0/enP2p4s0/' ../config.toml

(env RUST_BACKTRACE=1 RUST_LOG=INFO cargo run --release ../config.toml | grep -v Measurement) &> /tmp/ingrain.log &
sleep 3
pkill -9 cargo
