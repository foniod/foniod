use std::collections::HashMap;
use std::process::Command;
use std::sync::Arc;

use actix::prelude::*;
use rayon::prelude::*;
use regex::Regex as RegexMatcher;

use crate::backends::Message;
use crate::metrics::Measurement;

type Rules = Arc<HashMap<String, RegexMatcher>>;
pub struct Exec(ExecConfig, Rules, Recipient<Message>);
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ExecPattern {
    pub regex: String,
    pub key: String,
}
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ExecConfig {
    pub command: Vec<String>,
    pub only_if: Option<Vec<ExecPattern>>,
}

impl Exec {
    pub fn launch(config: ExecConfig, upstream: Recipient<Message>) -> Recipient<Message> {
        let rules = config
            .clone()
            .only_if
            .unwrap_or_default()
            .drain(..)
            .map(|p| (p.key, RegexMatcher::new(&p.regex).unwrap()))
            .collect();

        Exec(config, Arc::new(rules), upstream).start().recipient()
    }
}

impl Actor for Exec {
    type Context = Context<Self>;
}

impl Handler<Message> for Exec {
    type Result = ();

    fn handle(&mut self, mut msg: Message, _ctx: &mut Context<Self>) -> Self::Result {
        let command = &self.0.command;
        let rules = &self.1;
        match msg {
            Message::List(ref mut ms) => ms.par_iter().for_each(|m| run_command(command, rules, m)),
            Message::Single(ref mut m) => run_command(command, rules, m),
        }

        self.2.do_send(msg).unwrap();
    }
}

fn get_tag(msg: &Measurement, tag: &str) -> Option<String> {
    for (key, value) in msg.tags.iter() {
        if key == tag {
            return Some(value.to_string());
        }
    }

    None
}

fn run_command(command: &Vec<String>, rules: &Rules, msg: &Measurement) {
    // if there are no conditions, this _will_ run the command
    // filter_map ensures that only matching keys are considered
    if false
        == msg
            .tags
            .iter()
            .filter_map(|(k, v)| rules.get(k).map(|r| r.is_match(v)))
            .all(|x| x == true)
    {
        return;
    }

    let mut args = command.iter().map(|a| {
        let mut chars = a.chars();
        if chars.nth(0) == Some('{') && chars.last() == Some('}') {
            let t = get_tag(msg, a[1..a.len() - 1].trim());
            if t.is_some() {
                return t.unwrap();
            }
        }
        a.to_string()
    });

    Command::new(args.nth(0).unwrap())
        .args(args)
        .spawn()
        .expect("Failed to run command!");
}
