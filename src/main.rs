extern crate bcc;
extern crate libc;
extern crate failure;

use std::ptr;

use bcc::core::BPF;
use bcc::perf::init_perf_map;
use failure::Error;

const BPF_CODE: &'static str = include_str!("bpf.c");

/* 
 * Define the struct the BPF code writes in Rust
 * This must match the struct in `opensnoop.c` exactly.
 * The important thing to understand about the code in `opensnoop.c` is that it creates structs of
 * type `data_t` and pushes them into a buffer where our Rust code can read them.
 */
#[repr(C)]
#[derive(Debug)]
struct data_t {
    id: u64,
    ts: u64,
    comm: [u8; 16], // TASK_COMM_LEN
    saddr: u32,
    daddr: u32,
    dport: u16,
}

fn do_main() -> Result<(), Error> {
    let mut module = BPF::new(BPF_CODE)?;
    // load + attach kprobes!
    let return_probe = module.load_kprobe("trace_outbound_return")?;
    let entry_probe = module.load_kprobe("trace_outbound_entry")?;
    module.attach_kprobe("tcp_v4_connect", entry_probe)?;
    module.attach_kretprobe("tcp_v4_connect", return_probe)?;

    // the "events" table is where the "open file" events get sent
    let table = module.table("events");

    // install a callback to print out file open events when they happen
    let mut perf_map = init_perf_map(table, perf_data_callback)?;

    // print a header
    println!("{:-7} {:-16} {}", "PID", "COMM", "FILENAME");

    // this `.poll()` loop is what makes our callback get called
    loop {
        perf_map.poll(200);
    }
}

fn perf_data_callback() -> Box<FnMut(&[u8]) + Send> {
    Box::new(|x| {
        // This callback
        let data = parse_struct(x);
        println!("{:-7} {:-16}: {:#?}", data.id, get_string(&data.comm), data);
    })
}

fn parse_struct(x: &[u8]) -> data_t {
    unsafe { ptr::read(x.as_ptr() as *const data_t) }
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
