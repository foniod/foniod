use std::collections::HashMap;
use std::hash::Hasher;
use std::sync::Mutex;
use std::time::Duration;

use ::actix::prelude::*;
use futures::Future;
use metrohash::MetroHash128;

use crate::backends::{Flush, Message};
use crate::metrics::{Measurement, Tags, Unit};

pub struct Buffer(Mutex<HashMap<(u64, u64), Measurement>>, Recipient<Message>);
#[derive(Serialize, Deserialize, Debug)]
pub struct BufferConfig {
    pub interval_s: u64,
}

impl Actor for Buffer {
    type Context = Context<Self>;
}

impl Buffer {
    pub fn launch(config: BufferConfig, upstream: Recipient<Message>) -> Recipient<Message> {
        let interval = config.interval_s;
        Buffer::create(move |ctx| {
            ctx.run_interval(Duration::from_secs(interval), |_, ctx| {
                ctx.address().do_send(Flush)
            });

            Buffer(Mutex::new(HashMap::with_capacity(1024)), upstream)
        }).recipient()
    }

    fn add(&mut self, msg: Measurement) {
        self.0
            .lock()
            .unwrap()
            .entry(hash(&msg.name, &msg.tags))
            .and_modify(|e| {
                e.value = match e.value {
                    Unit::Byte(x) => Unit::Byte(x + msg.value.get()),
                    Unit::Count(x) => Unit::Count(x + msg.value.get()),
                }
            }).or_insert(msg);
    }
}

impl Handler<Message> for Buffer {
    type Result = ();

    fn handle(&mut self, msg: Message, _ctx: &mut Context<Self>) -> Self::Result {
        match msg {
            Message::List(mut ms) => for m in ms.drain(..) {
                self.add(m);
            },
            Message::Single(m) => self.add(m),
        }
    }
}

impl Handler<Flush> for Buffer {
    type Result = ();

    fn handle(&mut self, _: Flush, _ctx: &mut Context<Self>) -> Self::Result {
        let evs: Vec<Measurement> = {
            let mut buffer = self.0.lock().unwrap();
            buffer.drain().map(|(_, v)| v).collect()
        };

        if !evs.is_empty() {
            ::actix::spawn(self.1.send(Message::List(evs)).map_err(|_| ()));
        }
    }
}

fn hash(name: &str, tags: &Tags) -> (u64, u64) {
    let mut ctx = MetroHash128::new();
    ctx.write(name.as_bytes());

    for (k, v) in tags.iter() {
        ctx.write(k.as_bytes());
        ctx.write(v.as_bytes());
    }

    ctx.finish128()
}
