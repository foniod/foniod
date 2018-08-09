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
extern crate epoll;
extern crate lazy_socket;
extern crate metrohash;
extern crate redbpf;
extern crate rusoto_core;
extern crate rusoto_s3;
extern crate rustls;
extern crate serde_json;
extern crate tokio;
extern crate toml;
extern crate uuid;

use std::env;
use std::thread;

use actix::Actor;

mod aggregations;
mod backends;
mod config;
mod grains;
mod metrics;

use aggregations::{AddSystemDetails, Buffer};
use backends::{console::Console, s3, s3::S3, statsd::Statsd};
use config::BufferConfig;
use grains::*;

fn main() {
    let system = actix::System::new("userspace");
    let mut backends = vec![];

    // let app = vec![
    //     Grain::<tcpv4::TCP4>::load().unwrap().bind(vec![
    //         Pipeline {
    //             config: Backend::Statsd(StatsdConfig { use_tags: true }),
    //             steps: vec![
    //                 Aggregators::AddKernel,
    //                 Aggregators::AddHostname,
    //                 Aggregators::Holdback(HoldbackConfig { interval_s: 30 }),
    //             ],
    //         }.initialise(),
    //         Pipeline {
    //             config: Backend::Console(),
    //             steps: vec![]
    //         },
    //     ]);
    //     Grain::<udp::UDP>::load().unwrap().bind(backends.clone())
    // ];

    if let Ok(bucket) = env::var("AWS_BUCKET") {
        let interval_s = u64::from_str_radix(&env::var("AWS_INTERVAL").unwrap(), 10).unwrap();
        backends.push(Buffer::launch(
            &BufferConfig { interval_s },
            AddSystemDetails::launch(S3::new(s3::Region::EuWest2, bucket).start().recipient()),
        ));
    }

    // STATSD_TAG_WHITELIST="process,q_addr"

    if let (Ok(host), Ok(port)) = (env::var("STATSD_HOST"), env::var("STATSD_PORT")) {
        backends.push(AddSystemDetails::launch(
            Statsd::new(&host, u16::from_str_radix(&port, 10).unwrap())
                .start()
                .recipient(),
        ));
    }

    if let Ok(_) = env::var("CONSOLE") {
        backends.push(Console::start_default().recipient());
    }

    let panic_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic| {
        panic_hook(panic);
        std::process::exit(1);
    }));

    thread::spawn(move || {
        let mut grains: Vec<Box<dyn EventHandler>> = vec![];

        if let Ok(_) = env::var("FILES") {
            let mut files = file::Files.load().unwrap();
            grains.append(&mut files.attach_kprobes(&backends));
        }

        if let Ok(_) = env::var("NET_TCP") {
            let mut tcp_g = tcpv4::TCP4.load().unwrap();
            grains.append(&mut tcp_g.attach_kprobes(&backends));
        }

        if let Ok(_) = env::var("NET_UDP") {
            let mut udp_g = udp::UDP.load().unwrap();
            grains.append(&mut udp_g.attach_kprobes(&backends));
        }

        if let Ok(dns_if) = env::var("NET_DNS_TLS_IF") {
            let mut dns_g = dns::DNS.load().unwrap();
            grains.append(&mut dns_g.attach_xdps(&dns_if, &backends));

            let mut tls_g = tls::TLS.load().unwrap();
            grains.append(&mut tls_g.attach_socketfilters(&dns_if, &backends));
        }

        let _ = grains::epoll_loop(grains, 100).or_else::<(), _>(|err| {
            println!("Epoll failed: {}", err);
            std::process::exit(2);
        });
    });

    system.run();
}
