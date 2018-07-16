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
extern crate rusoto_core;
extern crate rusoto_s3;
extern crate serde_json;
extern crate toml;
extern crate uuid;

use std::env;
use std::thread;

mod aggregations;
mod backends;
mod config;
mod grains;
mod metrics;

use grains::*;

use actix::Actor;

use backends::{console::Console, s3, s3::S3, statsd::Statsd};

fn main() {
    let system = actix::System::new("outbound");

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
        use aggregations::Holdback;
        use config::HoldbackConfig;

        let interval_s = u64::from_str_radix(&env::var("AWS_INTERVAL").unwrap(), 10).unwrap();
        backends.push(Holdback::launch(
            &HoldbackConfig { interval_s },
            S3::new(s3::Region::EuWest2, bucket).start().recipient(),
        ));
    }

    if let (Ok(host), Ok(port)) = (env::var("STATSD_HOST"), env::var("STATSD_PORT")) {
        backends.push(
            Statsd::new(&host, u16::from_str_radix(&port, 10).unwrap())
                .start()
                .recipient(),
        );
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
        let mut grains: Vec<Box<dyn Pollable>> = vec![];

        grains.push(Box::new(Grain::<tcpv4::TCP4>::load()
                             .unwrap()
                             .attach_kprobes()
                             .bind(backends.clone())));

        grains.push(Box::new(Grain::<udp::UDP>::load()
                             .unwrap()
                             .attach_kprobes()
                             .bind(backends.clone())));

        if let Ok(dns_if) = env::var("DNS_IF") {
            grains.push(Box::new(Grain::<dns::DNS>::load()
                                 .unwrap()
                                 .attach_xdps(&dns_if)
                                 .bind(backends.clone())));
        }


        loop {
            for grain in grains.iter_mut() {
                grain.poll();
            }
        }
    });

    system.run();
}
