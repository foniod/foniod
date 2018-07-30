ingrainD
========

[![CircleCI](https://circleci.com/gh/redsift/ingraind.svg?style=svg)](https://circleci.com/gh/redsift/ingraind)

Data-first monitoring.

InGrain is a security monitoring software for complex containerized
environments and endpoints. The ingraind agent is built around eBPF probes to
provide safe and performant instrumentation for any Linux-based environment.

In conjunction with the RedSift Cloud, InGrain provides oversight of assets and
risks:
 * Your customer data - an employee copying your customer database to their
   personal cloud store.
 * Your infrastructure - an attacker executing a zero day attack to gain access
   to your web servers.
 * Your resources - malware using your users machines compute resources to mine
   cryptocurrency.

## Requirements
 
 * LLVM/Clang
 * Rust toolchain [rustup.rs](https://rustup.rs)
 * [BCC](https://github.com/iovisor/bcc)
 * Linux 4.4 or newer + headers
 
## Supported host OS

Currently, only Arch Linux is supported as a build environment. The kernel
version is dependent on `uname` output, so build cannot be trivially
containerised at the moment.

## Compile

Compilation on Arch Linux will pick up the currently installed source tree using
`pacman`.

On other distributions, set the `KERNEL_SOURCE` environment variable with the
path to the kernel source tree.

Please note that this actually needs to be a **dirty** source tree of an actual
kernel, not just a version compatible bare source tree.

The usual Rust compilation ritual will produce a binary in `target/release`:

    cargo build --release
    
To build a Docker container, make sure `kernel` directory is populated with the
source tree of the target kernel.

The resulting container is tagged `ingraind` by default, but you can set
additional tags or pass `docker` flags like so:

    docker/build.sh -t ingraind:$(git rev-parse HEAD | cut -c-7)
    
## Run

There are several environment variables that are picked up on start:
 * `AWS_ACCESS_KEY_ID=`: AWS access key
 * `AWS_SECRET_ACCESS_KEY=`: AWS secret key
 * `AWS_BUCKET=`: Target bucket for JSON files in S3
 * `AWS_INTERVAL=`: Commit interval for the S3 backend, in seconds
 * `STATSD_HOST=`: Host name/IP address of the statsd server
 * `STATSD_PORT=`: Statsd port
 * `CONSOLE=`: if present, raw data will be dumped to the console
 
The bare binary can be run as such:
 
    sudo RUST_BACKTRACE=1 \
         AWS_ACCESS_KEY_ID=xxx \
         AWS_SECRET_ACCESS_KEY="xxx" \
         AWS_BUCKET=xxx \
         AWS_INTERVAL=30 \
         ./target/release/ingraind
         
The docker container is portable even across kernel versions, but make sure that
the output is validated before putting it in production. Start it like so:

    docker run -e AWS_ACCESS_KEY_ID=xxx \
               -e AWS_SECRET_ACCESS_KEY="xxx"  \
               -e AWS_BUCKET=xxx \
               -e AWS_INTERVAL=10 \
               --name ingraind  \
               --pid=host  \
               --net=host  \
               --privileged  \
               -v /sys:/sys  \
               ingraind:latest
    
## Repo structure

The `bpf` directory contains the BPF modules. These are compiled by `build.rs`,
and embedded in the final binary, and will be managed by the grains.

On top of this, there are several crates that make up `ingraind`.
These are:

 * `bpf-sys`: Bindings to `libbpf.so`, a part of BCC. This is a ~40KiB `.so`, so
   easy to redistribute under Apache 2.
 * `redbpf`: High-level BPF runtime library. It loads ELF binaries, and handles
   `perf_event` interaction.
 * root: the main application code
 
# Anything else?

For more information, look at the [Wiki](https://github.com/redsift/ingraind/wiki)
