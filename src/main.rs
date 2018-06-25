#![cfg_attr(feature = "cargo-clippy", allow(clippy))]

extern crate chrono;
extern crate failure;
extern crate libc;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate cadence;
extern crate redbpf;
extern crate serde_json;
extern crate uuid;

use std::env;
use std::net::UdpSocket;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use cadence::{BufferedUdpMetricSink, QueuingMetricSink, StatsdClient, DEFAULT_PORT};

use chrono::DateTime;
use failure::Error;

mod grains;

use grains::Grain;

fn main() -> Result<(), Error> {
    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    socket.set_nonblocking(true).unwrap();

    let host = ("127.0.0.1", DEFAULT_PORT);
    let udp_sink = BufferedUdpMetricSink::from(host, socket).unwrap();
    let queuing_sink = QueuingMetricSink::from(udp_sink);
    let client = StatsdClient::from_udp_host("ingraind.metrics", host).unwrap();

    grains::tcpv4::TCP4::start(&client);

    // let instance_name =
    //     env::var("TCPSNIFF_ID").expect("Need to set INSTANCE_NAME environment variable");
    // let url_base = env::var("TCPSNIFF_URL").expect("Need to set SIFT_URL environment variable");
    // let events: Arc<Mutex<Vec<Connection>>> = Arc::new(Mutex::default());
    // let mut module = BPF::new(BPF_CODE)?;

    // // load + attach kprobes!
    // let return_probe = module.load_kprobe("trace_outbound_return")?;
    // let entry_probe = module.load_kprobe("trace_outbound_entry")?;
    // module.attach_kprobe("tcp_v4_connect", entry_probe)?;
    // module.attach_kretprobe("tcp_v4_connect", return_probe)?;

    // // the "events" table is where the "open file" events get sent
    // let table = module.table("events");

    // // install a callback to print out file open events when they happen
    // let mut perf_map = init_perf_map(table, || {
    //     let events = events.clone();
    //     Box::new(move |x| {
    //         // This callback
    //         let data = Connection::from(data_t::from(x));
    //         println!("{:-7} {:-16}: {:#?}", data.pid, &data.name, data);

    //         events
    //             .lock()
    //             .map(|mut e| {
    //                 e.push(data);
    //             })
    //             .unwrap();
    //     })
    // })?;

    // let reporter = thread::spawn(move || {
    //     let events = events.clone();

    //     loop {
    //         thread::sleep(Duration::from_secs(60));

    //         events
    //             .lock()
    //             .map(|mut data| {
    //                 Envelope::new(instance_name.clone(), Report::new(&data)).send(&url_base);
    //                 data.clear();
    //             })
    //             .unwrap();
    //     }
    // });

    // loop {
    //     perf_map.poll(200);
    // }
    Ok(())
}
