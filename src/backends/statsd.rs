use std::net::UdpSocket;

use actix::prelude::*;
use cadence::{BufferedUdpMetricSink, Counted, QueuingMetricSink, StatsdClient};

use backends::Message;
use metrics::Measurement;

pub struct Statsd {
    client: StatsdClient,
}

impl Statsd {
    pub fn new(host: &str, port: u16) -> Statsd {
        let helper_socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        helper_socket.set_nonblocking(true).unwrap();

        let udp_sink = BufferedUdpMetricSink::from((host, port), helper_socket).unwrap();
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
            Message::List(ref ms) => for mut m in ms {
                self.count_with_tags(&mut m);
            },
            Message::Single(ref m) => self.count_with_tags(m),
        }
    }
}
