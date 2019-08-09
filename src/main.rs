#![deny(clippy::all)]

#[macro_use]
extern crate actix;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate log;

use std::collections::HashMap;
use std::env;
use std::fs;
use std::thread;

mod aggregations;
mod backends;
mod config;
mod grains;
mod metrics;

use actix::Recipient;
use backends::Message;

#[cfg(feature = "capnp-encoding")]
mod ingraind_capnp {
    #![allow(clippy::all)]
    #![allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/schema/ingraind_capnp.rs"));
}

fn init_logging(config: &config::Config) {
    if let Some(ref backend) = config.log {
        use crate::config::Logging::*;
        use syslog::Facility;

        match backend {
            EnvLogger => env_logger::init(),
            Syslog(c) => syslog::init(Facility::LOG_USER, c.log_level, Some("ingraind"))
                .expect("Could not initialise syslog backend!"),
        };
    } else {
        env_logger::init();
    }
}

fn main() {
    let panic_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic| {
        panic_hook(panic);
        std::process::exit(1);
    }));

    let system = actix::System::new("userspace");

    let mut config: config::Config = {
        let file = env::args().nth(1).expect("Usage: ingraind <config file>");
        let content = fs::read(file).expect("Unable to read config file");
        toml::from_slice(content.as_slice()).expect("Error while parsing config file")
    };

    init_logging(&config);
    let backends = config
        .pipeline
        .drain()
        .map(|(key, pipeline)| {
            let mut backend = pipeline.backend.into_recipient();
            let mut steps = pipeline.steps.unwrap_or_else(|| vec![]);
            steps.reverse();

            for step in steps.drain(..) {
                backend = step.into_recipient(backend);
            }

            (key, backend)
        })
        .collect::<HashMap<String, Recipient<Message>>>();

    thread::spawn(move || {
        let epollables = config
            .probe
            .drain(..)
            .flat_map(|probe| {
                let mut grain = probe.grain.into_grain();
                let pipelines = probe
                    .pipelines
                    .iter()
                    .map(|p| {
                        backends
                            .get(p)
                            .unwrap_or_else(|| panic!("Invalid configuration: pipeline {} not found!", p))
                            .clone()
                    })
                    .collect::<Vec<Recipient<Message>>>();

                grain.to_eventoutputs(pipelines.as_slice())
            })
            .collect();

        let _ = grains::epoll_loop(epollables, 100).or_else::<(), _>(|err| {
            error!("Epoll failed: {}", err);
            std::process::exit(2);
        });
    });

    system.run().unwrap();
}
