execvesniff-rs
===========

On start, tcpsniff-rs injects a BPF tracer for the `sys_execve` call, and
then collects the events coming out of the kernel.
This requires a working LLVM toolchain, along with kernel headers installed on
the host where execvesniff-rs is *ran*.

## Requirements
 
 * LLVM
 * Rust toolchain [rustup.rs](https://rustup.rs)
 * [BCC](https://github.com/iovisor/bcc)
 * Linux 4.4 or newer

## Compile

The usual Rust compilation ritual will produce a binary in `target/release`:

    cargo build --release
    
## Run

Because execvesniff-rs messes with the kernel, it needs elevated privileges to run,
or the `CAP_SYS_ADMIN` capability (for all BPF-related calls) and a
`/proc/sys/kernel/perf_event_paranoid` value of less than 1 (see `man 2
perf_event_open`).

To keep things simple, let's use `sudo -E`:
    
    env WEBHOOK=localhost:10000 INSTANCE_NAME=random sudo -E ./target/release/tcpsniff-rs

## Bugs

Retrieving command arguments doesn't seem to be working properly. I have not
had the chance to debug why exactly, but it looks like the `argv` array is
consistently filled with 0 bytes.
The corresponding Python code can be found in the [bcc
repository](https://github.com/iovisor/bcc/blob/master/tools/execsnoop.py), but
I could also not bring the Python bindings to life.
