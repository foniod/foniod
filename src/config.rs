use std::collections::HashMap;

use actix::{Actor, Recipient};

use aggregations::*;
use backends::*;
use grains::{dns, file, tcpv4, tls, udp};
use grains::{EBPFGrain, ToEpollHandler};

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub probe: Vec<Probe>,
    pub pipeline: HashMap<String, Pipeline>,
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
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "backend")]
pub enum Backend {
    S3,
    StatsD(statsd::StatsdConfig),
    Console,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum Aggregator {
    AddSystemDetails,
    Buffer(BufferConfig),
    Regex(RegexConfig),
    Whitelist(WhitelistConfig),
}

impl Aggregator {
    pub fn into_recipient(self, upstream: Recipient<Message>) -> Recipient<Message> {
        match self {
            Aggregator::AddSystemDetails => AddSystemDetails::launch(upstream),
            Aggregator::Buffer(config) => Buffer::launch(config, upstream),
            Aggregator::Regex(config) => Regex::launch(config, upstream),
            Aggregator::Whitelist(config) => Whitelist::launch(config, upstream),
        }
    }
}

impl Backend {
    pub fn into_recipient(self) -> Recipient<Message> {
        match self {
            Backend::S3 => s3::S3::new().start().recipient(),
            Backend::StatsD(config) => statsd::Statsd::new(config).start().recipient(),
            Backend::Console => console::Console.start().recipient(),
        }
    }
}

impl Grain {
    pub fn into_grain(self) -> Box<dyn ToEpollHandler> {
        match self {
            Grain::TCP4 => Box::new(tcpv4::TCP4.load().unwrap()),
            Grain::UDP => Box::new(udp::UDP.load().unwrap()),
            Grain::Files(config) => Box::new(file::Files(config).load().unwrap()),
            Grain::DNS(config) => Box::new(dns::DNS(config).load().unwrap()),
            Grain::TLS(config) => Box::new(tls::TLS(config).load().unwrap()),
        }
    }
}

mod tests {
    #[test]
    fn can_parse() {
        use config::Config;
        use toml;

        let config: Config = toml::from_str(
            r#"
[[probe]]
pipelines = ["statsd"]
[probe.config]
type = "Files"
monitor_dirs = ["/"]

[[probe]]
pipelines = ["statsd"]
[probe.config]
type = "TCP4"

[pipeline.statsd.config]
backend = "StatsD"
use_tags = true

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
        ).unwrap();
    }
}
