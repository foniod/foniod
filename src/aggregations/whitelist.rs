use actix::prelude::*;
use rayon::prelude::*;
use std::collections::HashSet;
use std::sync::Arc;

use crate::backends::Message;
use crate::metrics::Measurement;

pub struct Whitelist(Arc<HashSet<String>>, Recipient<Message>);
#[derive(Serialize, Deserialize, Debug)]
pub struct WhitelistConfig {
    pub allow: Vec<String>,
}

impl Whitelist {
    pub fn launch(mut config: WhitelistConfig, upstream: Recipient<Message>) -> Recipient<Message> {
        Whitelist(Arc::new(config.allow.drain(..).collect()), upstream)
            .start()
            .recipient()
    }
}

impl Actor for Whitelist {
    type Context = Context<Self>;
}

fn filter_tags(msg: &mut Measurement, whitelist: Arc<HashSet<String>>) {
    msg.tags.0.retain(|(k, _v)| whitelist.contains(k));
}

impl Handler<Message> for Whitelist {
    type Result = ();

    fn handle(&mut self, mut msg: Message, _ctx: &mut Context<Self>) -> Self::Result {
        let whitelist = self.0.clone();
        match msg {
            Message::List(ref mut ms) => ms
                .par_iter_mut()
                .for_each(move |m| filter_tags(m, whitelist.clone())),
            Message::Single(ref mut m) => filter_tags(m, whitelist.clone()),
        }

        self.1.do_send(msg).unwrap();
    }
}
