use actix::{Actor, AsyncContext, Context, Recipient, StreamHandler};
use futures::{Async, Poll, Stream};
use std::cmp;
use std::time::Duration;
use tokio_timer::Interval;

use crate::backends::Message;
use crate::grains::SendToManyRecipients;
use crate::metrics::{kind, timestamp_now, Measurement, Tags, Unit};

pub struct TestProbe {
    config: TestProbeConfig,
    recipients: Vec<Recipient<Message>>,
}

impl TestProbe {
    pub fn with_config(config: TestProbeConfig, recipients: Vec<Recipient<Message>>) -> Self {
        TestProbe { config, recipients }
    }
}

impl Actor for TestProbe {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        info!("debug probe started {:?}", std::thread::current().id());
        let unit = Unit::try_from_str(
            &self.config.measurement_type,
            self.config.measurement.parse().unwrap_or_default(),
        )
        .unwrap();
        let kind = kind::try_from_str(&self.config.aggregation_type.as_ref().unwrap()).unwrap();
        ctx.add_stream(MeasurementStream::new(
            self.config.name.clone(),
            unit,
            kind,
            self.config.tags.clone(),
            self.config.message_len,
            self.config.measurements_per_second,
        ));
    }

    fn stopped(&mut self, _ctx: &mut Self::Context) {
        info!("debug daemon stopped");
    }
}

impl StreamHandler<Message, ()> for TestProbe {
    fn handle(&mut self, message: Message, _ctx: &mut Context<TestProbe>) {
        self.recipients.do_send(message);
    }
}

pub struct MeasurementStream {
    name: String,
    unit: Unit,
    kind: kind::Kind,
    tags: Vec<Tag>,
    message_len: usize,
    ms_per_second: usize,
    ms_sent: usize,
    interval: Interval,
}

impl MeasurementStream {
    fn new(
        name: String,
        unit: Unit,
        kind: kind::Kind,
        tags: Vec<Tag>,
        message_len: usize,
        ms_per_second: usize,
    ) -> Self {
        MeasurementStream {
            name,
            unit,
            kind,
            tags,
            message_len,
            ms_per_second,
            ms_sent: 0,
            interval: Interval::new_interval(Duration::from_secs(1)),
        }
    }
}

impl Stream for MeasurementStream {
    type Item = Message;
    type Error = ();

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        if let Ok(Async::Ready(_)) = self.interval.poll() {
            self.ms_sent = 0;
        }
        if self.ms_sent < self.ms_per_second {
            let message_len = cmp::min(self.message_len, self.ms_per_second - self.ms_sent);
            self.ms_sent += message_len;
            let measurements = (0..message_len)
                .map(|_| {
                    let mut tags = Tags::new();
                    for (key, value) in &self.tags {
                        let value = match value.as_str() {
                            "$TS" => format!("{}", timestamp_now()),
                            _ => value.clone(),
                        };
                        tags.insert(key.clone(), value);
                    }
                    Measurement::new(self.kind, self.name.clone(), self.unit.clone(), tags)
                })
                .collect();
            let message = Message::List(measurements);
            return Ok(Async::Ready(Some(message)));
        }
        Ok(Async::NotReady)
    }
}

pub type Tag = (String, String);

fn default_ms_per_second() -> usize {
    10000
}

fn default_message_len() -> usize {
    5000
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TestProbeConfig {
    name: String,
    measurement: String,
    measurement_type: String,
    aggregation_type: Option<String>,
    tags: Vec<Tag>,
    #[serde(default = "default_ms_per_second")]
    measurements_per_second: usize,
    #[serde(default = "default_message_len")]
    message_len: usize,
}
