use actix::prelude::*;
use cadence::{BufferedUdpMetricSink, Counted, QueuingMetricSink, StatsdClient};

use metrics::Measurement;

use std::net::UdpSocket;

pub struct Statsd {
    client: StatsdClient,
}

impl Statsd {
    pub fn new(host: &str, port: u16) -> Statsd {
        let helper_socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        helper_socket.set_nonblocking(true).unwrap();

        let udp_sink = BufferedUdpMetricSink::from((host, port), helper_socket).unwrap();
        let queuing_sink = QueuingMetricSink::from(udp_sink);
        let client = StatsdClient::from_udp_host("ingraind.metrics", (host, port)).unwrap();

        Statsd { client }
    }
}

impl Actor for Statsd {
    type Context = Context<Self>;
}

impl actix::Message for Measurement {
    type Result = u8;
}

impl Handler<Measurement> for Statsd {
    type Result = u8;

    fn handle(&mut self, msg: Measurement, ctx: &mut Context<Self>) -> Self::Result {
        println!("{:?}", msg);
        0
        // let mut builder = self.client.count_with_tags(&msg.name, msg.value);
        // for (key, value) in msg.tags.iter() {
        //     builder = builder.with_tag(key, value);
        // }

        // builder.try_send().unwrap();

        // 0
    }
}
