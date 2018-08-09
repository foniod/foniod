use actix::prelude::*;
use futures::Future;

use backends::Message;
use metrics::Measurement;

pub struct TagWhitelist(Vec<String>, Recipient<Message>);
impl Actor for TagWhitelist {
    type Context = Context<Self>;
}

impl TagWhitelist {
    pub fn launch(allow: Vec<String>, upstream: Recipient<Message>) -> Recipient<Message> {
        TagWhitelist(allow, upstream).start().recipient()
    }

    fn filter_tags(&self, msg: &mut Measurement) {
        msg.tags.0.retain(|(k, _v)| self.0.contains(k));
    }
}

impl Handler<Message> for TagWhitelist {
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
