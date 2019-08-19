use std::collections::HashMap;
use std::convert::From;
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
}

#[derive(Clone, Debug, PartialEq)]
enum MetricValue {
    Counter(f64),
    Timing(f64),
    Gauge(f64, bool),
}

#[derive(Debug, Eq, PartialEq)]
enum MetricError {
    Error,
    ValueError,
    TypeError,
    SampleRateError,
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

    let (value, ty, sample_rate) = {
        let mut parts = value.splitn(3, '|');
        let value = parts.next().ok_or(ValueError).and_then(|v| {
            if v.is_empty() {
                Err(ValueError)
            } else {
                Ok(v)
            }
        })?;
        let ty = parts.next().ok_or(TypeError).and_then(|ty| {
            if ty.is_empty() {
                Err(TypeError)
            } else {
                Ok(ty)
            }
        })?;

        let sample_rate: Option<f64> = match parts.next() {
            Some(s) if s.is_empty() => return Err(SampleRateError),
            Some(s) => Some(s[1..].parse().map_err(|_| SampleRateError)?),
            None => None,
        };
        (value, ty, sample_rate)
    };

    let value = match ty {
        "c" => MetricValue::Counter(value.parse().map_err(|_| ValueError)?),
        "g" => {
            let first = value.chars().nth(0).unwrap();
            let reset = !(first == '+' || first == '-');
            let value = value.parse().map_err(|_| ValueError)?;
            MetricValue::Gauge(value, reset)
        }
        "ms" => MetricValue::Timing(value.parse().map_err(|_| ValueError)?),
        _ => return Err(TypeError),
    };

    Ok(Metric {
        key,
        value,
        sample_rate,
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

#[derive(Debug)]
struct Aggregator {
    counters: HashMap<String, f64>,
    gauges: HashMap<String, f64>,
    timers: HashMap<String, Vec<f64>>,
}

impl Aggregator {
    pub fn new() -> Self {
        Aggregator {
            counters: HashMap::new(),
            gauges: HashMap::new(),
            timers: HashMap::new(),
        }
    }

    pub fn record(&mut self, metric: Metric) -> Metric {
        use MetricValue::*;

        let Metric {
            key,
            value,
            sample_rate,
        } = metric;

        let k = key.clone();
        let v = match value {
            Counter(mut v) => {
                if let Some(srate) = sample_rate {
                    v /= srate;
                }
                Counter(*self.counters
                    .entry(key)
                    .and_modify(|c| *c += v)
                    .or_insert(v))
            }
            Gauge(v, reset) => {
                Gauge(*self.gauges
                    .entry(key)
                    .and_modify(|g| if reset { *g = v } else { *g += v })
                    .or_insert(v), reset)
            }
            Timing(v) => {
                self.timers.entry(key).or_default().push(v);
                Timing(v)
            }
        };

        Metric { key: k, value: v, sample_rate }
    }

    fn flush(&mut self) {
        self.counters.clear();
        self.gauges.clear();
        self.timers.clear();
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
            .map(|m| self.aggregator.record(m).into())
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

        let tags = Tags::new();
        Measurement::new(k, self.key, Unit::Count(v as u64), tags)
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
                sample_rate: None
            })
        );
        assert_eq!(
            parse_metric("foo:1|c|@0.1"),
            Ok(Metric {
                key: "foo".to_string(),
                value: MetricValue::Counter(1f64),
                sample_rate: Some(0.1)
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
                sample_rate: None
            })
        );
        assert_eq!(
            parse_metric("foo:320|ms|@0.1"),
            Ok(Metric {
                key: "foo".to_string(),
                value: MetricValue::Timing(320f64),
                sample_rate: Some(0.1)
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
                sample_rate: None
            })
        );
        assert_eq!(
            parse_metric("foo:+42|g"),
            Ok(Metric {
                key: "foo".to_string(),
                value: MetricValue::Gauge(42f64, false),
                sample_rate: None
            })
        );
        assert_eq!(
            parse_metric("foo:-42|g"),
            Ok(Metric {
                key: "foo".to_string(),
                value: MetricValue::Gauge(-42f64, false),
                sample_rate: None
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
        assert_eq!(parse_metric("foo:1234|ms|"), Err(SampleRateError));
        assert_eq!(parse_metric("foo:1234|ms|bar"), Err(SampleRateError));
        assert_eq!(parse_metric("foo:1|g|@bar"), Err(SampleRateError));
        assert_eq!(parse_metric("foo:bar|c"), Err(ValueError));
        assert_eq!(parse_metric("foo:*42|g"), Err(ValueError));
    }

    #[test]
    fn test_parse_metrics_one() {
        let metrics = parse_metrics("foo:1|c").unwrap();
        assert_eq!(
            metrics,
            &[Metric {
                key: "foo".to_string(),
                value: MetricValue::Counter(1f64),
                sample_rate: None
            }]
        );
        let metrics = parse_metrics("foo:1|c\n").unwrap();
        assert_eq!(
            metrics,
            &[Metric {
                key: "foo".to_string(),
                value: MetricValue::Counter(1f64),
                sample_rate: None
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
                    sample_rate: None
                },
                Metric {
                    key: "bar".to_string(),
                    value: MetricValue::Timing(100f64),
                    sample_rate: None
                }
            ]
        )
    }
}
