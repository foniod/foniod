#![cfg_attr(feature = "cargo-clippy", allow(clippy:all))]

#[macro_use]
extern crate actix;
extern crate failure;
extern crate futures;
extern crate libc;
extern crate serde;
#[macro_use]
extern crate serde_derive;
#[cfg(feature = "statsd-backend")]
extern crate cadence;
extern crate epoll;
#[cfg(feature = "http-backend")]
extern crate hyper;
#[cfg(feature = "http-backend")]
extern crate hyper_rustls;
extern crate lazy_socket;
extern crate metrohash;
extern crate redbpf;
extern crate regex;
#[cfg(feature = "s3-backend")]
extern crate rusoto_core;
#[cfg(feature = "s3-backend")]
extern crate rusoto_s3;
extern crate rustls;
extern crate serde_json;
extern crate tokio;
extern crate toml;
extern crate uuid;

use std::collections::HashMap;
use std::env;
use std::fs;
use std::thread;

mod aggregations;
mod backends;
mod config;
mod grains;
mod metrics;

use grains::*;

use actix::Recipient;

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

    let backends = config
        .pipeline
        .drain()
        .map(|(key, mut pipeline)| {
            let mut backend = pipeline.backend.into_recipient();
            let mut steps = pipeline.steps.unwrap_or(vec![]);
            steps.reverse();

            for step in steps.drain(..) {
                backend = step.into_recipient(backend);
            }

            (key, backend)
        }).collect::<HashMap<String, Recipient<Message>>>();

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
                            .expect(&format!("Invalid configuration: pipeline {} not found!", p))
                            .clone()
                    }).collect::<Vec<Recipient<Message>>>();

                grain.to_eventoutputs(pipelines.as_slice())
            }).collect();

        let _ = grains::epoll_loop(epollables, 100).or_else::<(), _>(|err| {
            println!("Epoll failed: {}", err);
            std::process::exit(2);
        });
    });

    system.run();
}
