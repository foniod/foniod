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

use grains::*;

fn main() -> Result<(), Error> {
    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    socket.set_nonblocking(true).unwrap();

    let host = ("127.0.0.1", DEFAULT_PORT);
    let udp_sink = BufferedUdpMetricSink::from(host, socket).unwrap();
    let queuing_sink = QueuingMetricSink::from(udp_sink);
    let client = StatsdClient::from_udp_host("ingraind.metrics", host).unwrap();

    let mut mod_udp = grains::udp::UDP::start();
    let mut perf_udp = mod_udp.perfmaps(&client);

    let mut mod_tcp4 = grains::tcpv4::TCP4::start();
    let mut perf_tcp4 = mod_tcp4.perfmaps(&client);

    loop {
        thread::sleep(Duration::from_secs(1));

        for pm in perf_udp.iter_mut() {
            pm.poll(10)
        }
        for pm in perf_tcp4.iter_mut() {
            pm.poll(10)
        }
    }

    Ok(())
}
