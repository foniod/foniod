use std::collections::HashMap;
use std::sync::Arc;

use actix::prelude::*;
use rayon::prelude::*;
use regex::Regex as RegexMatcher;

use crate::backends::Message;
use crate::metrics::Measurement;

type Rules = Arc<HashMap<String, (RegexMatcher, String)>>;
pub struct Regex(Rules, Recipient<Message>);
#[derive(Serialize, Deserialize, Debug)]
pub struct RegexPattern {
    pub regex: String,
    pub replace_with: String,
    pub key: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RegexConfig {
    pub patterns: Vec<RegexPattern>,
}

impl Regex {
    pub fn launch(mut config: RegexConfig, upstream: Recipient<Message>) -> Recipient<Message> {
        let rules = config
            .patterns
            .drain(..)
            .map(|p| {
                (
                    p.key,
                    (RegexMatcher::new(&p.regex).unwrap(), p.replace_with),
                )
            })
            .collect();

        Regex(Arc::new(rules), upstream).start().recipient()
    }
}

impl Actor for Regex {
    type Context = Context<Self>;
}

fn filter_tags(msg: &mut Measurement, rules: Rules) {
    for (key, value) in msg.tags.iter_mut() {
        if let Some((regex, replace)) = rules.get(key) {
            if regex.is_match(value) {
                *value = replace.clone();
            }
        }
    }
}

impl Handler<Message> for Regex {
    type Result = ();

    fn handle(&mut self, mut msg: Message, _ctx: &mut Context<Self>) -> Self::Result {
        let rules = self.0.clone();
        match msg {
            Message::List(ref mut ms) => ms
                .par_iter_mut()
                .for_each(move |m| filter_tags(m, rules.clone())),
            Message::Single(ref mut m) => filter_tags(m, rules),
        }

        self.1.do_send(msg).unwrap();
    }
}
