TCPSniff-rs
===========

At the moment, all this program does is collecting information about outgoing
connections from a host.
An example of the produced payload can be found in
[example_payload.json](./example_payload.json).

On start, tcpsniff-rs injects a BPF tracer for the `tcp_v4_connect` call, and
then collects the events coming out of the kernel.
This requires a working LLVM toolchain, along with kernel headers installed on
the host where tcpsniff-rs is *ran*.

## Requirements
 
 * LLVM
 * Rust toolchain [rustup.rs](https://rustup.rs)
 * [BCC](https://github.com/iovisor/bcc)
 * Linux 4.4 or newer

## Compile

The usual Rust compilation ritual will produce a binary in `target/release`:

    cargo build --release
    
## Run

Configuration is received through environment variables:

 * `TCPSNIFF_ID`: the name to use in reports 
 * `TCPSNIFF_URL`: a URL stub where reports are sent to. `$WEBHOOK/<uuid v4>` is used as a destination.
 
Because tcpsniff-rs messes with the kernel, it needs elevated privileges to run,
or the `CAP_SYS_ADMIN` capability (for all BPF-related calls) and a
`/proc/sys/kernel/perf_event_paranoid` value of less than 1 (see `man 2
perf_event_open`).

To keep things simple, let's use `sudo -E`:
    
    env WEBHOOK=localhost:10000 INSTANCE_NAME=random sudo -E ./target/release/tcpsniff-rs
