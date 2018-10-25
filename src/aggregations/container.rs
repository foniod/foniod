use std::fs;
use std::str::FromStr;

use actix::prelude::*;
use failure::{format_err, Error};
use futures::Future;
use lazy_static::lazy_static;
use regex::Regex;

use backends::Message;
use metrics::Measurement;

lazy_static! {
    // this pattern actually matches the Docker id from both
    // Kubernetes and Docker-created containers
    static ref DOCKER_PATTERN: Regex = Regex::new(r#":/.*/([a-z0-9]{64})$"#).unwrap();
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ContainerConfig;
pub struct Container(ContainerConfig, Recipient<Message>);

impl Actor for Container {
    type Context = Context<Self>;
}

impl Container {
    pub fn launch(config: ContainerConfig, upstream: Recipient<Message>) -> Recipient<Message> {
        Container(config, upstream)
            .start()
            .recipient()
    }

    fn add_tags(&self, msg: &mut Measurement) {
        if let Ok(cid) = get_docker_container_id(&DOCKER_PATTERN, msg) {
            msg.tags.insert("docker_id", cid);
        }
    }
}

impl Handler<Message> for Container {
    type Result = ();

    fn handle(&mut self, mut msg: Message, _ctx: &mut Context<Self>) -> Self::Result {
        match msg {
            Message::List(ref mut ms) => {
                for mut m in ms {
                    self.add_tags(&mut m);
                }
            }
            Message::Single(ref mut m) => self.add_tags(m),
        }

        ::actix::spawn(self.1.send(msg).map_err(|_| ()));
    }
}

#[inline]
fn get_docker_container_id(regex: &Regex, msg: &Measurement) -> Result<String, Error> {
    let pid_tgid_str = msg.tags.get("task_id").ok_or(format_err!("No pid"))?;
    let pid_tgid = u64::from_str(&pid_tgid_str)?;
    let tgid = pid_tgid >> 32;
    let pid = pid_tgid as u32;

    let cgroup = fs::read_to_string(format!("/proc/{}/task/{}/cgroup", tgid, pid))?;

    container_id(regex, &cgroup).ok_or(format_err!("No container"))
}

#[inline]
fn container_id(re: &Regex, cgroup: &str) -> Option<String> {
    for container in re.captures_iter(cgroup) {
        return container.get(1).map(|m| m.as_str().to_string());
    }

    None
}
