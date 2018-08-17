use actix::prelude::*;
use futures::Future;

use backends::Message;
use metrics::Measurement;

pub struct Whitelist(Vec<String>, Recipient<Message>);
#[derive(Serialize, Deserialize, Debug)]
pub struct WhitelistConfig {
    pub allow: Vec<String>,
}

impl Whitelist {
    pub fn launch(config: WhitelistConfig, upstream: Recipient<Message>) -> Recipient<Message> {
        Whitelist(config.allow, upstream).start().recipient()
    }

    fn filter_tags(&self, msg: &mut Measurement) {
        msg.tags.0.retain(|(k, _v)| self.0.contains(k));
    }
}

impl Actor for Whitelist {
    type Context = Context<Self>;
}

impl Handler<Message> for Whitelist {
    type Result = ();

    fn handle(&mut self, mut msg: Message, _ctx: &mut Context<Self>) -> Self::Result {
        match msg {
            Message::List(ref mut ms) => for mut m in ms {
                self.filter_tags(&mut m);
            },
            Message::Single(ref mut m) => self.filter_tags(m),
        }

        ::actix::spawn(self.1.send(msg).map_err(|_| ()));
    }
}
