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
        let mut mod_tcp4 = Grain::<tcpv4::TCP4>::load().unwrap().bind(&backend);
        let mut mod_udp = Grain::<udp::UDP>::load().unwrap().bind(&backend);

        loop {
            mod_tcp4.poll();
            mod_udp.poll();
        }
    });

    system.run();
}
