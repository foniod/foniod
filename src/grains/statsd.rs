use std::convert::From;
use std::io;
use std::net::SocketAddr;
use std::str;

use actix::{Actor, AsyncContext, Context, Recipient, Running, StreamHandler};
use bytes::BytesMut;
use tokio::codec;
use tokio_udp::{UdpFramed, UdpSocket};

use crate::grains::SendToManyRecipients;
use crate::backends::Message;
use crate::metrics::{kind, Measurement, Tags, Unit};

#[derive(Clone, Debug, PartialEq)]
pub struct Metric {
    key: String,
    value: MetricValue,
    sample_rate: Option<f64>,
    tags: Tags,
}

#[derive(Clone, Debug, PartialEq)]
pub enum MetricValue {
    Counter(f64),
    Timing(f64),
    Gauge(f64, bool),
    Set(String),
    Histogram(u64),
}

#[derive(Debug, Eq, PartialEq)]
pub enum MetricError {
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

pub fn parse_metric(input: &str) -> Result<Metric, MetricError> {
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
    recipients: Vec<Recipient<Message>>,
}

impl Statsd {
    pub fn new(bind_address: SocketAddr, recipients: Vec<Recipient<Message>>) -> Self {
        Statsd {
            bind_address,
            recipients,
        }
    }

    pub fn with_config(config: StatsdConfig, recipients: Vec<Recipient<Message>>) -> Self {
        Self::new(
            config.bind_address.parse().unwrap(), // FIXME: don't unwrap
            recipients,
        )
    }
}

impl Actor for Statsd {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        info!("statsd daemon started {}", self.bind_address);
        let socket = UdpSocket::bind(&self.bind_address).unwrap();
        let metrics = UdpFramed::new(socket, Decoder);
        ctx.add_stream(metrics);
    }

    fn stopped(&mut self, _ctx: &mut Self::Context) {
        info!("statsd daemon stopped");
    }
}

impl StreamHandler<(Vec<Metric>, SocketAddr), DecoderError> for Statsd {
    fn handle(
        &mut self,
        (metrics, _src_addr): (Vec<Metric>, SocketAddr),
        _ctx: &mut Context<Statsd>,
    ) {
        let message: Message = metrics.into();
        self.recipients.do_send(message);
    }

    fn error(&mut self, err: DecoderError, _ctx: &mut Self::Context) -> Running {
        error!("error parsing metrics {:?}", err);
        Running::Continue
    }
}

fn default_bind_address() -> String {
    "127.0.0.1:8125".to_string()
}

#[derive(Serialize, Deserialize, Debug)]
pub struct StatsdConfig {
    #[serde(default = "default_bind_address")]
    pub bind_address: String,
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
        use kind::*;
        use Unit::*;

        let mut reset = false;
        let (k, v) = match self.value {
            Counter(v) => (COUNTER, Count(v as u64)),
            Gauge(v, rst) => {
                reset = rst;
                (GAUGE, Count(v as u64))
            }
            Timing(t) => (TIMER, Count(t as u64)),
            Set(v) => (SET, Str(v)),
            Histogram(v) => (HISTOGRAM, Count(v))
        };

        let mut m = Measurement::new(k, self.key, v, self.tags);
        m.reset = reset;
        m.sample_rate = self.sample_rate;
        m
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
}
