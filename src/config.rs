use std::collections::HashMap;

use actix::{Actor, Arbiter, Recipient};
use log::LevelFilter;

use crate::aggregations::*;
use crate::backends::*;
use crate::grains::{self, dns, file, syscalls, tcpv4, tls, udp, osquery};
use crate::grains::{EBPFActor, EBPFGrain, EBPFProbe};

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub log: Option<Logging>,
    pub probe: Vec<Probe>,
    pub pipeline: HashMap<String, Pipeline>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum Logging {
    EnvLogger,
    Syslog(SyslogConfig),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SyslogConfig {
    pub log_level: LevelFilter,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Probe {
    pub pipelines: Vec<String>,
    #[serde(rename = "config")]
    pub grain: Grain,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Pipeline {
    #[serde(rename = "config")]
    pub backend: Backend,
    pub steps: Option<Vec<Aggregator>>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum Grain {
    Files(file::FilesConfig),
    TCP4,
    UDP,
    DNS(dns::DnsConfig),
    TLS(tls::TlsConfig),
    Syscall(syscalls::SyscallConfig),
    StatsD(grains::statsd::StatsdConfig),
    Osquery(osquery::OsqueryConfig)
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "backend")]
pub enum Backend {
    #[cfg(feature = "s3-backend")]
    S3,
    #[cfg(feature = "statsd-backend")]
    StatsD(statsd::StatsdConfig),
    #[cfg(feature = "http-backend")]
    HTTP(http::HTTPConfig),
    Console,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum Aggregator {
    AddSystemDetails,
    Buffer(BufferConfig),
    Regex(RegexConfig),
    Whitelist(WhitelistConfig),
    Container(ContainerConfig),
}

impl Aggregator {
    pub fn into_recipient(self, upstream: Recipient<Message>) -> Recipient<Message> {
        match self {
            Aggregator::AddSystemDetails => AddSystemDetails::launch(upstream),
            Aggregator::Buffer(config) => Buffer::launch(config, upstream),
            Aggregator::Regex(config) => Regex::launch(config, upstream),
            Aggregator::Whitelist(config) => Whitelist::launch(config, upstream),
            Aggregator::Container(config) => Container::launch(config, upstream),
        }
    }
}

impl Backend {
    pub fn into_recipient(self) -> Recipient<Message> {
        match self {
            #[cfg(feature = "s3-backend")]
            Backend::S3 => Actor::start_in_arbiter(&actix::Arbiter::new(), |_| s3::S3::new()).recipient(),
            #[cfg(feature = "statsd-backend")]
            Backend::StatsD(config) => Actor::start_in_arbiter(&actix::Arbiter::new(), |_| statsd::Statsd::new(config)).recipient(),
            #[cfg(feature = "http-backend")]
            Backend::HTTP(config) => Actor::start_in_arbiter(&actix::Arbiter::new(), |_| http::HTTP::new(config)).recipient(),
            Backend::Console => console::Console.start().recipient(),
        }
    }
}

pub enum ProbeActor {
    EBPF(EBPFActor),
    StatsD(grains::statsd::Statsd),
    Osquery(osquery::Osquery)
}

impl ProbeActor {
    pub fn start(self, io: &Arbiter) {
        match self {
            ProbeActor::EBPF(a) => { Actor::start_in_arbiter(io, |_| a); },
            ProbeActor::StatsD(a) => { Actor::start_in_arbiter(io, |_| a); }
            ProbeActor::Osquery(a) => { a.start(); }
        };
    }
}

impl Grain {
    pub fn into_probe_actor(self, recipients: Vec<Recipient<Message>>) -> ProbeActor {
        match self {
            Grain::StatsD(config) => ProbeActor::StatsD(grains::statsd::Statsd::with_config(config, recipients)),
            Grain::Osquery(config) => ProbeActor::Osquery(osquery::Osquery::with_config(config, recipients)),
            _ => {
                    let probe: Box<dyn EBPFProbe> = match self {
                        Grain::TCP4 => Box::new(tcpv4::TCP4.load().unwrap()),
                        Grain::UDP => Box::new(udp::UDP.load().unwrap()),
                        Grain::Files(config) => Box::new(file::Files(config).load().unwrap()),
                        Grain::DNS(config) => Box::new(dns::DNS(config).load().unwrap()),
                        Grain::TLS(config) => Box::new(tls::TLS(config).load().unwrap()),
                        Grain::Syscall(config) => Box::new(syscalls::Syscall(config).load().unwrap()),
                        _ => unreachable!()
                };
                ProbeActor::EBPF(EBPFActor::new(probe, recipients))
            }
        }
    }
}

mod tests {
    #[test]
    fn can_parse() {
        use crate::config::Config;
        use toml;

        let _config: Config = toml::from_str(
            r#"
[log]
type = "Syslog"
log_level = "DEBUG"

[[probe]]
pipelines = ["statsd"]
[probe.config]
type = "Files"
monitor_dirs = ["/"]

[[probe]]
pipelines = ["statsd", "http"]
[probe.config]
type = "TCP4"

[[probe]]
pipelines = ["statsd"]
[probe.config]
type = "Syscall"
monitor_syscalls = ["read"]

[pipeline.http.config]
backend = "HTTP"
encoding = "JSON"
uri = "https://example.com/"
[pipeline.http.config.headers]

[pipeline.statsd.config]
backend = "StatsD"
use_tags = true

[[pipeline.statsd.steps]]
type = "Container"

[[pipeline.statsd.steps]]
type = "Whitelist"
allow = ["k1", "k2"]

[[pipeline.statsd.steps]]
type = "Regex"
patterns = [
  { key = "some_key", regex = ".*", replace_with = "some_value"},
  { key = "some_key2", regex = ".*", replace_with = "some_value2"},
]

[[pipeline.statsd.steps]]
type = "AddSystemDetails"

[[pipeline.statsd.steps]]
type = "Buffer"
interval_s = 30
"#,
        )
        .unwrap();
    }
}
