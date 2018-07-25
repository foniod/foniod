use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use actix::prelude::*;
use futures::Future;
use ring::digest;

use backends::{Flush, Message};
use config::BufferConfig;
use metrics::{Measurement, Unit};

pub struct Buffer(Mutex<HashMap<Vec<u8>, Measurement>>, Recipient<Message>);
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

            Buffer(Mutex::new(HashMap::new()), upstream)
        }).recipient()
    }

    fn add(&mut self, msg: &Measurement) {
        self.0
            .lock()
            .unwrap()
            .entry(hash(&msg.name, &msg.tags))
            .and_modify(|e| {
                e.value = match e.value {
                    Unit::Byte(x) => Unit::Byte(x + msg.value.get()),
                    Unit::Count(x) => Unit::Count(x + msg.value.get()),
                }
            })
            .or_insert(msg.clone());
    }
}

impl Handler<Message> for Buffer {
    type Result = ();

    fn handle(&mut self, mut msg: Message, _ctx: &mut Context<Self>) -> Self::Result {
        match msg {
            Message::List(ref mut ms) => for m in ms.drain(..) {
                self.add(&m);
            },
            Message::Single(ref m) => self.add(m),
        }
    }
}

impl Handler<Flush> for Buffer {
    type Result = ();

    fn handle(&mut self, _: Flush, _ctx: &mut Context<Self>) -> Self::Result {
        let evs: Vec<Measurement> = {
            let mut buffer = self.0.lock().unwrap();
            let evs = buffer.drain().map(|(_, v)| v).collect();

            evs
        };

        if evs.len() == 0 {
            return;
        }

        ::actix::spawn(self.1.send(Message::List(evs)).map_err(|_| ()));
    }
}

fn hash(name: &str, tags: &HashMap<String, String>) -> Vec<u8> {
    let mut ctx = digest::Context::new(&digest::SHA256);
    ctx.update(name.as_bytes());

    let mut lst: Vec<(&String, &String)> = tags.iter().collect();
    lst.sort_by(|a, b| a.0.cmp(&b.0));

    for (k, v) in lst.iter() {
        ctx.update(k.as_bytes());
        ctx.update(v.as_bytes());
    }

    ctx.finish().as_ref().to_vec()
}
