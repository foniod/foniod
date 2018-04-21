extern crate bcc;
extern crate chrono;
extern crate failure;
extern crate libc;
extern crate reqwest;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate uuid;

use std::env;
use std::net::Ipv4Addr;
use std::ptr;
use std::sync::{Mutex, Arc};
use std::thread;
use std::time::Duration;

use bcc::core::BPF;
use bcc::perf::init_perf_map;
use chrono::DateTime;
use failure::Error;

const BPF_CODE: &'static str = include_str!("bpf.c");

//
// Define the struct the BPF code writes in Rust.
// This must match `struct data_t` in `bpf.c`
#[repr(C)]
struct data_t {
    pid: u32,
    comm: [u8; 16],
    event_type: u8,
    argv: [u8; 16],
    retval: i32,
}

impl<'a> From<&'a [u8]> for data_t {
    fn from(x: &'a [u8]) -> data_t {
        unsafe { ptr::read(x.as_ptr() as *const data_t) }
    }
}

fn do_main() -> Result<(), Error> {
    let mut module = BPF::new(BPF_CODE)?;

    // load + attach kprobes!
    let return_probe = module.load_kprobe("sys_execve")?;
    let entry_probe = module.load_kprobe("ret_sys_execve")?;
    module.attach_kprobe("sys_execve", entry_probe)?;
    module.attach_kretprobe("sys_execve", return_probe)?;

    // the "events" table is where the "open file" events get sent
    let table = module.table("events");

    // install a callback to print out file open events when they happen
    let mut perf_map = init_perf_map(table, || {
        Box::new(move |x| {
            // This callback
            let data = data_t::from(x);
            println!("{:-7} {:-16}: {:?}", data.pid, get_string(&data.comm), &data.argv);
        })
    })?;

    loop {
        perf_map.poll(200);
    }
}

fn get_string(x: &[u8]) -> String {
    match x.iter().position(|&r| r == 0) {
        Some(zero_pos) => String::from_utf8_lossy(&x[0..zero_pos]).to_string(),
        None => String::from_utf8_lossy(x).to_string(),
    }
}

fn main() {
    match do_main() {
        Err(x) => {
            eprintln!("Error: {}", x);
            eprintln!("{}", x.backtrace());
            std::process::exit(1);
        }
        _ => {}
    }
}
