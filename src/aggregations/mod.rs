use std::sync::Mutex;
use std::time::Duration;

//// Split here ////
use actix::prelude::*;
use futures::Future;

use backends::{Flush, Message};
use config::*;
use metrics::Measurement;

pub struct AddSystemDetails(String, String, Recipient<Message>);
pub struct Holdback(Mutex<Vec<Measurement>>, Recipient<Message>);

impl Actor for AddSystemDetails {
    type Context = Context<Self>;
}

impl AddSystemDetails {
    pub fn launch(upstream: Recipient<Message>) -> Recipient<Message> {
        use redbpf::uname::*;

        let uts = uname().unwrap();
        let kernel = to_str(&uts.release).to_string();

        AddSystemDetails(get_fqdn().unwrap(), kernel, upstream)
            .start()
            .recipient()
    }

    fn add_tags(&self, msg: &mut Measurement) {
        msg.tags.insert("host".to_string(), self.0.clone());
        msg.tags.insert("kernel".to_string(), self.1.clone());
    }
}

impl Handler<Message> for AddSystemDetails {
    type Result = ();

    fn handle(&mut self, mut msg: Message, _ctx: &mut Context<Self>) -> Self::Result {
        match msg {
            Message::List(ref mut ms) => for mut m in ms {
                self.add_tags(&mut m);
            },
            Message::Single(ref mut m) => self.add_tags(m),
        }

        ::actix::spawn(self.2.send(msg).map_err(|_| ()));
    }
}

impl Actor for Holdback {
    type Context = Context<Self>;
}

impl Holdback {
    pub fn launch(config: &HoldbackConfig, upstream: Recipient<Message>) -> Recipient<Message> {
        let interval = config.interval_s;
        Holdback::create(move |ctx| {
            ctx.run_interval(Duration::from_secs(interval), |_, ctx| {
                ctx.address().do_send(Flush)
            });

            Holdback(Mutex::new(vec![]), upstream)
        }).recipient()
    }
}

impl Handler<Message> for Holdback {
    type Result = ();

    fn handle(&mut self, mut msg: Message, _ctx: &mut Context<Self>) -> Self::Result {
        match msg {
            Message::List(ref mut ms) => self.0.lock().unwrap().extend(ms.drain(..)),
            Message::Single(ref m) => self.0.lock().unwrap().push(m.clone()),
        }
    }
}

impl Handler<Flush> for Holdback {
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
