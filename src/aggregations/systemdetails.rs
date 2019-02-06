use ::actix::prelude::*;
use futures::Future;

use crate::backends::Message;
use crate::metrics::Measurement;

pub struct AddSystemDetails(String, String, Recipient<Message>);
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
