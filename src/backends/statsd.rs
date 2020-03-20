use std::env;
use std::net::UdpSocket;
use std::str::FromStr;

use ::actix::prelude::*;
use cadence::{BufferedUdpMetricSink, Counted, QueuingMetricSink, StatsdClient};

use crate::backends::Message;
use crate::metrics::Measurement;

pub struct Statsd {
    client: StatsdClient,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct StatsdConfig {
    pub use_tags: bool,
}

impl Statsd {
    pub fn new(_config: StatsdConfig) -> Statsd {
        let helper_socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        helper_socket.set_nonblocking(true).unwrap();

        let host =
            env::var("STATSD_HOST").expect("The STATSD_HOST environment variable has to be set!");
        let port =
            env::var("STATSD_PORT").expect("The STATSD_PORT environment variable has to be set!");
        let port = u16::from_str(&port).expect("STATSD_PORT has to be a valid port number");

        let udp_sink = BufferedUdpMetricSink::from((host.as_str(), port), helper_socket)
            .unwrap_or_else(|_| panic!("Invalid statsd server settings: {}:{}", host, port));
        let queuing_sink = QueuingMetricSink::from(udp_sink);
        let client = StatsdClient::from_sink("ingraind.metrics", queuing_sink);

        Statsd { client }
    }

    fn count_with_tags(&mut self, msg: &Measurement) {
        let mut builder = self
            .client
            .count_with_tags(&msg.name, msg.value.get() as i64);
        for (key, value) in msg.tags.iter() {
            builder = builder.with_tag(key, value);
        }

        builder.try_send().unwrap();
    }
}

impl Actor for Statsd {
    type Context = Context<Self>;
}

impl Handler<Message> for Statsd {
    type Result = ();

    fn handle(&mut self, msg: Message, _ctx: &mut Context<Self>) -> Self::Result {
        match msg {
            Message::List(ref ms) => {
                for m in ms {
                    self.count_with_tags(&m);
                }
            }
            Message::Single(ref m) => self.count_with_tags(m),
        }
    }
}
