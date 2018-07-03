#![cfg_attr(feature = "cargo-clippy", allow(clippy))]

#[macro_use]
extern crate actix;
extern crate failure;
extern crate futures;
extern crate libc;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate cadence;
extern crate redbpf;
extern crate serde_json;
extern crate uuid;

use std::thread;
use std::time::Duration;

mod backends;
mod grains;
mod metrics;
use grains::*;

use actix::Actor;

fn main() {
    let system = actix::System::new("outbound");
    let addr = backends::Statsd::new("127.0.0.1", 8125);
    let backend = addr.start().recipient();

    thread::spawn(move || {
        let mut mod_tcp4 = grains::tcpv4::TCP4::load().unwrap();
        let mut perf_tcp4 = grains::tcpv4::TCP4::bind(&mut mod_tcp4, &backend);

        // let mut mod_udp = grains::udp::UDP::load().unwrap();
        // let mut perf_udp = grains::udp::UDP::bind(&mut mod_udp, &client);

        loop {
            // for pm in perf_udp.iter_mut() {
            //     pm.poll(10)
            // }
            for pm in perf_tcp4.iter_mut() {
                pm.poll(10)
            }
        }
    });

    system.run();
}
