use std::sync::Mutex;
use std::time::Duration;

use actix::prelude::*;
use futures::Future;

use backends::{Flush, Message};
use config::BufferConfig;
use metrics::Measurement;

pub struct Buffer(Mutex<Vec<Measurement>>, Recipient<Message>);
impl Actor for Buffer {
    type Context = Context<Self>;
}

impl Buffer {
    pub fn launch(config: &BufferConfig, upstream: Recipient<Message>) -> Recipient<Message> {
        let interval = config.interval_s;
        Buffer::create(move |ctx| {
            ctx.run_interval(Duration::from_secs(interval), |_, ctx| {
                ctx.address().do_send(Flush)
            });

            Buffer(Mutex::new(vec![]), upstream)
        }).recipient()
    }
}

impl Handler<Message> for Buffer {
    type Result = ();

    fn handle(&mut self, mut msg: Message, _ctx: &mut Context<Self>) -> Self::Result {
        match msg {
            Message::List(ref mut ms) => self.0.lock().unwrap().extend(ms.drain(..)),
            Message::Single(ref m) => self.0.lock().unwrap().push(m.clone()),
        }
    }
}

impl Handler<Flush> for Buffer {
    type Result = ();

    fn handle(&mut self, _: Flush, _ctx: &mut Context<Self>) -> Self::Result {
        let evs = {
            let mut buffer = self.0.lock().unwrap();
            let evs = buffer.clone();
            buffer.clear();

            evs
        };

        if evs.len() == 0 {
            return;
        }

        ::actix::spawn(self.1.send(Message::List(evs)).map_err(|_| ()));
    }
}
