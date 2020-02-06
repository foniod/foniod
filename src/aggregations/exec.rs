use std::process::Command;
use std::sync::Arc;

use actix::prelude::*;
use rayon::prelude::*;

use crate::backends::Message;
use crate::metrics::Measurement;

pub struct Exec(ExecConfig, Recipient<Message>);
#[derive(Serialize, Deserialize, Debug)]
pub struct ExecConfig {
    pub command: String,
    pub arguments: Vec<String>,
}

impl Exec {
    pub fn launch(config: ExecConfig, upstream: Recipient<Message>) -> Recipient<Message> {
        Exec(config, upstream).start().recipient()
    }
}

impl Actor for Exec {
    type Context = Context<Self>;
}

impl Handler<Message> for Exec {
    type Result = ();

    fn handle(&mut self, mut msg: Message, _ctx: &mut Context<Self>) -> Self::Result {
        let rules = &self.0;
        match msg {
            Message::List(ref mut ms) => ms.par_iter_mut().for_each(move |m| run_command(rules, m)),
            Message::Single(ref mut m) => run_command(rules, m),
        }

        self.1.do_send(msg).unwrap();
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

fn run_command(conf: &ExecConfig, msg: &Measurement) {
    let args = conf.arguments.iter().map(|a| {
        let mut chars = a.chars();
        if chars.nth(0) == Some('{') && chars.last() == Some('}') {
            let t = get_tag(msg, a[1..a.len() - 1].trim());
            if t.is_some() {
                return t.unwrap();
            }
        }
        a.to_string()
    });

    Command::new(&conf.command).args(args).spawn().expect("Failed to run command!");
}
