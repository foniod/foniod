#![deny(clippy::all)]

use std::collections::HashMap;
use std::env;
use std::fs;

use actix::Recipient;
use ingraind::{backends::Message, config};

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
    let io = actix::Arbiter::new();

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

    let probe_actors: Vec<_> = config
        .probe
        .drain(..)
        .map(|probe| {
            let recipients = probe
                .pipelines
                .iter()
                .map(|p| {
                    backends
                        .get(p)
                        .unwrap_or_else(|| panic!("Invalid configuration: pipeline {} not found!", p))
                        .clone()
                })
                .collect::<Vec<Recipient<Message>>>();
            probe.grain.into_probe_actor(recipients)
        })
        .collect();

    for actor in probe_actors {
        actor.start(&io);
    }

    system.run().unwrap();
}
