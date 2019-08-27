use std::collections::{HashMap, HashSet};
use std::convert::From;
use std::hash::{Hash, Hasher};
use std::cmp::Eq;
use std::io;
use std::net::SocketAddr;
use std::str;
use std::time::Duration;

use actix::utils::IntervalFunc;
use actix::{
    Actor, ActorStream, AsyncContext, Context, ContextFutureSpawner, Recipient, Running,
    StreamHandler,
};
use bytes::BytesMut;
use tokio::codec;
use tokio_udp::{UdpFramed, UdpSocket};

use crate::backends::Message;
use crate::metrics::{kind, Measurement, Tags, Unit};

#[derive(Clone, Debug, PartialEq)]
struct Metric {
    key: String,
    value: MetricValue,
    sample_rate: Option<f64>,
    tags: Tags,
}

impl Metric {
    pub fn update(&mut self, other: Metric) -> Result<(), MetricError> {
        use MetricValue::*;

        let Metric {
            key,
            value,
            sample_rate,
            mut tags,
        } = other;

        if self.key != key {
            return Err(MetricError::Error);
        }

        match (&mut self.value, value) {
            (Counter(ref mut v), Counter(mut new_v)) => {
                if let Some(s_rate) = sample_rate {
                    new_v /= s_rate;
                }
                *v += new_v;
            }
            (Gauge(ref mut v, ref mut reset), Gauge(new_v, new_reset)) => {
                *reset = new_reset;
                if new_reset {
                    *v = new_v;
                } else {
                    *v += new_v;
                }
            }
            (Timing(ref mut v), Timing(new_v)) => {
                *v = new_v;
            }
            (Set(ref mut v), Set(ref new_v)) => {
                *v = new_v.clone();
            }
            _ => return Err(MetricError::Error),
        };

        self.tags.append(&mut tags);

        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq)]
enum MetricValue {
    Counter(f64),
    Timing(f64),
    Gauge(f64, bool),
    Set(String),
    Histogram(u64),
}

#[derive(Debug, Eq, PartialEq)]
enum MetricError {
    Error,
    ValueError,
    TypeError,
    SampleRateError,
    TagError,
}

struct Decoder;

#[derive(Debug)]
enum DecoderError {
    MetricError(MetricError),
    IOError(io::Error),
}

impl From<MetricError> for DecoderError {
    fn from(e: MetricError) -> DecoderError {
        DecoderError::MetricError(e)
    }
}

impl From<io::Error> for DecoderError {
    fn from(e: io::Error) -> DecoderError {
        DecoderError::IOError(e)
    }
}

fn parse_metric(input: &str) -> Result<Metric, MetricError> {
    use MetricError::*;

    let mut parts = input.splitn(2, ':');
    let key = parts.next().ok_or(Error)?.to_string();
    let value = parts.next().ok_or(Error)?;
    let mut sample_rate: Option<f64> = None;
    let mut tags = Tags::new();

    let (value, ty, rest) = {
        let mut parts = value.split('|');
        let value = parts.next().filter(|v| !v.is_empty()).ok_or(ValueError)?;
        let ty = parts.next().filter(|v| !v.is_empty()).ok_or(TypeError)?;

        (value, ty, parts)
    };

    for part in rest {
        match part.chars().next() {
            Some('@') => sample_rate = Some(part[1..].parse().map_err(|_| SampleRateError)?),
            Some('#') => {
                let mut parts = part[1..].splitn(2, ":");
                let key = parts.next().filter(|v| !v.is_empty()).ok_or(TagError)?;
                let value = parts.next().filter(|v| !v.is_empty()).ok_or(TagError)?;
                tags.insert(key, value);
            }
            _ => return Err(Error),
        }
    }

    let value = match ty {
        "c" => MetricValue::Counter(value.parse().map_err(|_| ValueError)?),
        "g" => {
            let first = value.chars().nth(0).unwrap();
            let reset = !(first == '+' || first == '-');
            let value = value.parse().map_err(|_| ValueError)?;
            MetricValue::Gauge(value, reset)
        }
        "ms" => MetricValue::Timing(value.parse().map_err(|_| ValueError)?),
        "s" => MetricValue::Set(value.to_string()),
        "h" => MetricValue::Histogram(value.parse().map_err(|_| ValueError)?),
        _ => return Err(TypeError),
    };

    Ok(Metric {
        key,
        value,
        sample_rate,
        tags,
    })
}

fn parse_metrics(input: &str) -> Result<Vec<Metric>, MetricError> {
    let mut metrics = Vec::new();
    for line in input.lines() {
        let metric = parse_metric(line)?;
        metrics.push(metric);
    }

    Ok(metrics)
}

#[derive(Clone, Debug)]
struct SetMetric(Metric);

impl Hash for SetMetric {
    fn hash<H: Hasher>(&self, state: &mut H) {
        use MetricValue::*;
        match &self.0.value {
            Set(value) => {
                self.0.key.hash(state);
                value.hash(state);
            }
            _ => unreachable!()
        }
    }
}

impl PartialEq for SetMetric {
    fn eq(&self, other: &Self) -> bool {
        use MetricValue::*;
        match (&self.0.value, &other.0.value) {
            (Set(value), Set(other_value)) => {
                self.0.key == other.0.key && value == other_value
            }
            _ => false
        }
    }
}

impl Eq for SetMetric {}

#[derive(Debug)]
struct Aggregator {
    counters: HashMap<String, Metric>,
    gauges: HashMap<String, Metric>,
    timers: HashMap<String, Vec<Metric>>,
    sets: HashMap<String, HashSet<SetMetric>>
}

impl Aggregator {
    pub fn new() -> Self {
        Aggregator {
            counters: HashMap::new(),
            gauges: HashMap::new(),
            timers: HashMap::new(),
            sets: HashMap::new()
        }
    }

    pub fn record(&mut self, metric: Metric) -> Metric {
        use std::collections::hash_map::Entry::*;
        use MetricValue::*;

        let key = metric.key.clone();
        match &metric.value {
            Counter(_) | Gauge(_, _) => {
                match self.counters.entry(key.clone()) {
                    Vacant(e) => {
                        e.insert(metric.clone());
                        metric
                    }
                    Occupied(mut e) => {
                        e.get_mut().update(metric).unwrap();
                        self.counters.get(&key).unwrap().clone()
                    }
                }
            }
            Timing(_) => {
                let timers = self.timers.entry(key).or_default();
                timers.push(metric.clone());
                metric
            }
            Set(_) => {
                let set = self.sets.entry(key).or_default();
                set.insert(SetMetric(metric.clone()));
                metric

            }
        }
    }

    pub fn uniques(&self, key: &str) -> Option<usize> {
        self.sets.get(key).map(|s| s.len())
    }

    fn flush(&mut self) {
        self.counters.clear();
        self.gauges.clear();
        self.timers.clear();
        self.sets.clear();
    }
}

impl codec::Decoder for Decoder {
    type Item = Vec<Metric>;
    type Error = DecoderError;

    fn decode(&mut self, input: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if input.is_empty() {
            return Ok(None);
        }

        let bytes = input.take();
        let input = str::from_utf8(&bytes).map_err(|_| MetricError::Error)?;
        let metrics = parse_metrics(input)?;
        Ok(Some(metrics))
    }
}

pub struct Statsd {
    bind_address: SocketAddr,
    flush_interval: Duration,
    aggregator: Aggregator,
    recipients: Vec<Recipient<Message>>,
}

impl Statsd {
    pub fn new(
        bind_address: SocketAddr,
        flush_interval: Duration,
        recipients: Vec<Recipient<Message>>,
    ) -> Self {
        Statsd {
            bind_address,
            flush_interval,
            aggregator: Aggregator::new(),
            recipients,
        }
    }

    pub fn with_config(config: StatsdConfig, recipients: Vec<Recipient<Message>>) -> Self {
        Self::new(
            config.bind_address.parse().unwrap(), // FIXME: don't unwrap
            Duration::from_millis(config.flush_interval.parse().unwrap()),
            recipients,
        )
    }

    fn flush(&mut self, _ctx: &mut Context<Self>) {
        info!("flushing");
        self.aggregator.flush();
    }
}

impl Actor for Statsd {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        info!("statsd daemon started {}", self.bind_address);
        let socket = UdpSocket::bind(&self.bind_address).unwrap();
        let metrics = UdpFramed::new(socket, Decoder);
        IntervalFunc::new(self.flush_interval, Self::flush)
            .finish()
            .spawn(ctx);
        ctx.add_stream(metrics);
    }

    fn stopped(&mut self, _ctx: &mut Self::Context) {
        info!("statsd daemon stopped");
    }
}

impl StreamHandler<(Vec<Metric>, SocketAddr), DecoderError> for Statsd {
    fn handle(
        &mut self,
        (mut metrics, _src_addr): (Vec<Metric>, SocketAddr),
        _ctx: &mut Context<Statsd>,
    ) {
        let aggregated: Vec<Metric> = metrics
            .drain(..)
            .map(|m| self.aggregator.record(m).clone().into())
            .collect();
        let measurements: Message = aggregated.into();
        for recipient in &self.recipients {
            recipient.do_send(measurements.clone()).unwrap();
        }
    }

    fn error(&mut self, err: DecoderError, _ctx: &mut Self::Context) -> Running {
        error!("error parsing metrics {:?}", err);
        Running::Continue
    }
}

fn default_bind_address() -> String {
    "127.0.0.1:8125".to_string()
}

fn default_flush_interval() -> String {
    "10000".to_string()
}

#[derive(Serialize, Deserialize, Debug)]
pub struct StatsdConfig {
    #[serde(default = "default_bind_address")]
    pub bind_address: String,
    #[serde(default = "default_flush_interval")]
    pub flush_interval: String,
}

impl Into<Message> for Metric {
    fn into(self) -> Message {
        Message::Single(self.into())
    }
}

impl Into<Message> for Vec<Metric> {
    fn into(self) -> Message {
        if self.len() == 1 {
            Message::Single(self.get(0).unwrap().clone().into())
        } else {
            let measurements: Vec<Measurement> =
                self.iter().cloned().map(|metric| metric.into()).collect();
            Message::List(measurements)
        }
    }
}

impl Into<Measurement> for Metric {
    fn into(self) -> Measurement {
        use MetricValue::*;

        let (k, v) = match self.value {
            Counter(v) => (kind::COUNTER, v),
            Gauge(v, _reset) => (kind::GAUGE, v),
            _ => unimplemented!(),
        };

        Measurement::new(k, self.key, Unit::Count(v as u64), self.tags)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_counter() {
        assert_eq!(
            parse_metric("foo:1|c"),
            Ok(Metric {
                key: "foo".to_string(),
                value: MetricValue::Counter(1f64),
                sample_rate: None,
                tags: Tags::new()
            })
        );
        assert_eq!(
            parse_metric("foo:1|c|@0.1"),
            Ok(Metric {
                key: "foo".to_string(),
                value: MetricValue::Counter(1f64),
                sample_rate: Some(0.1),
                tags: Tags::new()
            })
        );
    }

    #[test]
    fn test_parse_timer() {
        assert_eq!(
            parse_metric("foo:320|ms"),
            Ok(Metric {
                key: "foo".to_string(),
                value: MetricValue::Timing(320f64),
                sample_rate: None,
                tags: Tags::new()
            })
        );
        assert_eq!(
            parse_metric("foo:320|ms|@0.1"),
            Ok(Metric {
                key: "foo".to_string(),
                value: MetricValue::Timing(320f64),
                sample_rate: Some(0.1),
                tags: Tags::new()
            })
        );
    }

    #[test]
    fn test_parse_gauge() {
        assert_eq!(
            parse_metric("foo:42|g"),
            Ok(Metric {
                key: "foo".to_string(),
                value: MetricValue::Gauge(42f64, true),
                sample_rate: None,
                tags: Tags::new()
            })
        );
        assert_eq!(
            parse_metric("foo:+42|g"),
            Ok(Metric {
                key: "foo".to_string(),
                value: MetricValue::Gauge(42f64, false),
                sample_rate: None,
                tags: Tags::new()
            })
        );
        assert_eq!(
            parse_metric("foo:-42|g"),
            Ok(Metric {
                key: "foo".to_string(),
                value: MetricValue::Gauge(-42f64, false),
                sample_rate: None,
                tags: Tags::new()
            })
        );
    }

    #[test]
    fn test_parse_set() {
        assert_eq!(
            parse_metric("foo:42|s"),
            Ok(Metric {
                key: "foo".to_string(),
                value: MetricValue::Set("42".into()),
                sample_rate: None,
                tags: Tags::new()
            })
        );
    }

    #[test]
    fn test_parse_tags_one() {
        let mut tags = Tags::new();
        tags.insert("bar", "baz");
        assert_eq!(
            parse_metric("foo:1|c|#bar:baz"),
            Ok(Metric {
                key: "foo".to_string(),
                value: MetricValue::Counter(1f64),
                sample_rate: None,
                tags: tags
            })
        );
    }

    #[test]
    fn test_parse_tags_many() {
        let mut tags = Tags::new();
        tags.insert("bar", "baz");
        tags.insert("bao", "bab");
        assert_eq!(
            parse_metric("foo:1|c|#bar:baz|#bao:bab"),
            Ok(Metric {
                key: "foo".to_string(),
                value: MetricValue::Counter(1f64),
                sample_rate: None,
                tags: tags
            })
        );
    }

    #[test]
    fn test_parse_metric_errors() {
        use MetricError::*;

        assert_eq!(parse_metric(""), Err(Error));
        assert_eq!(parse_metric("foo"), Err(Error));
        assert_eq!(parse_metric("foo:"), Err(ValueError));
        assert_eq!(parse_metric("foo:bar"), Err(TypeError));
        assert_eq!(parse_metric("foo:bar|"), Err(TypeError));
        assert_eq!(parse_metric("foo:bar|baz"), Err(TypeError));
        assert_eq!(parse_metric("foo:1234|ms|"), Err(Error));
        assert_eq!(parse_metric("foo:1234|ms|bar"), Err(Error));
        assert_eq!(parse_metric("foo:1|g|@bar"), Err(SampleRateError));
        assert_eq!(parse_metric("foo:bar|c"), Err(ValueError));
        assert_eq!(parse_metric("foo:*42|g"), Err(ValueError));
        assert_eq!(parse_metric("foo:1|g|#"), Err(TagError));
        assert_eq!(parse_metric("foo:1|g|#foo"), Err(TagError));
        assert_eq!(parse_metric("foo:1|g|#foo:"), Err(TagError));
    }

    #[test]
    fn test_parse_metrics_one() {
        let mut tags = Tags::new();
        tags.insert("bar", "baz");
        let metrics = parse_metrics("foo:1|c|@0.5|#bar:baz").unwrap();
        assert_eq!(
            metrics,
            &[Metric {
                key: "foo".to_string(),
                value: MetricValue::Counter(1f64),
                sample_rate: Some(0.5),
                tags: tags
            }]
        );
        let metrics = parse_metrics("foo:1|c\n").unwrap();
        assert_eq!(
            metrics,
            &[Metric {
                key: "foo".to_string(),
                value: MetricValue::Counter(1f64),
                sample_rate: None,
                tags: Tags::new()
            }]
        );
    }

    #[test]
    fn test_parse_metrics_multi() {
        let metrics = parse_metrics("foo:1|c\nbar:100|ms").unwrap();
        assert_eq!(
            metrics,
            &[
                Metric {
                    key: "foo".to_string(),
                    value: MetricValue::Counter(1f64),
                    sample_rate: None,
                    tags: Tags::new()
                },
                Metric {
                    key: "bar".to_string(),
                    value: MetricValue::Timing(100f64),
                    sample_rate: None,
                    tags: Tags::new()
                }
            ]
        )
    }

    #[test]
    fn test_aggregate_counter() {
        let mut aggregator = Aggregator::new();
        let m1 = parse_metric("foo:1|c").unwrap();
        let m2 = parse_metric("foo:2|c").unwrap();
        let m3 = parse_metric("foo:3|c").unwrap();
        assert_eq!(aggregator.record(m1.clone()), m1);
        assert_eq!(aggregator.record(m2.clone()), m3);
    }

    #[test]
    fn test_aggregate_gauge() {
        let mut aggregator = Aggregator::new();
        let m1 = parse_metric("foo:1|g").unwrap();
        let m2 = parse_metric("foo:2|g").unwrap();
        let m3 = parse_metric("foo:+3|g").unwrap();
        let m4 = parse_metric("foo:+5|g").unwrap();
        let m5 = parse_metric("foo:-6|g").unwrap();
        let m6 = parse_metric("foo:-1|g").unwrap();
        assert_eq!(aggregator.record(m1.clone()), m1);
        assert_eq!(aggregator.record(m2.clone()), m2);
        assert_eq!(aggregator.record(m3.clone()), m4);
        assert_eq!(aggregator.record(m5), m6);
    }

    #[test]
    fn test_aggregate_set() {
        let mut aggregator = Aggregator::new();
        let m1 = parse_metric("foo:bar|s").unwrap();
        let m2 = parse_metric("foo:bad|s").unwrap();
        let m3 = parse_metric("bar:foo|s").unwrap();
        assert_eq!(aggregator.uniques("foo"), None);
        aggregator.record(m1.clone());
        assert_eq!(aggregator.uniques("foo"), Some(1));
        aggregator.record(m1);
        assert_eq!(aggregator.uniques("foo"), Some(1));
        aggregator.record(m2);
        assert_eq!(aggregator.uniques("foo"), Some(2));
        aggregator.record(m3);
        assert_eq!(aggregator.uniques("bar"), Some(1));
    }
}
