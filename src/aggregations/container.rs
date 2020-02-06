use std::fs;
use std::str::FromStr;

use actix::prelude::*;
use failure::{format_err, Error};
use lazy_static::lazy_static;
use rayon::prelude::*;
use regex::Regex;

use crate::backends::Message;
use crate::metrics::Measurement;

lazy_static! {
    // this pattern actually matches the Docker id from both
    // Kubernetes and Docker-created containers
    static ref DOCKER_PATTERN: Regex = Regex::new(r#"(?m):/.*/([a-z0-9]{64})$"#).unwrap();
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ContainerConfig;
pub struct Container(ContainerConfig, Recipient<Message>);

impl Actor for Container {
    type Context = Context<Self>;
}

impl Container {
    pub fn launch(config: ContainerConfig, upstream: Recipient<Message>) -> Recipient<Message> {
        Container(config, upstream).start().recipient()
    }
}

fn add_tags(msg: &mut Measurement) {
    if let Ok(cid) = get_docker_container_id(&DOCKER_PATTERN, msg) {
        msg.tags.insert("docker_id", cid);
    }
}

impl Handler<Message> for Container {
    type Result = ();

    fn handle(&mut self, mut msg: Message, _ctx: &mut Context<Self>) -> Self::Result {
        match msg {
            Message::List(ref mut ms) => ms.par_iter_mut().for_each(move |m| add_tags(m)),
            Message::Single(ref mut m) => add_tags(m),
        }

        self.1.do_send(msg).unwrap();
    }
}

#[inline]
fn get_docker_container_id(regex: &Regex, msg: &Measurement) -> Result<String, Error> {
    let pid_tgid_str = msg
        .tags
        .get("task_id")
        .ok_or_else(|| format_err!("No pid"))?;
    let pid_tgid = u64::from_str(&pid_tgid_str)?;
    let tgid = pid_tgid >> 32;
    let pid = pid_tgid as u32;

    let cgroup = fs::read_to_string(format!("/proc/{}/task/{}/cgroup", tgid, pid))
        .or_else(|_| fs::read_to_string(format!("/proc/{}/cgroup", pid)))?;

    container_id(regex, &cgroup).ok_or_else(|| format_err!("No container"))
}

#[inline]
fn container_id(re: &Regex, cgroup: &str) -> Option<String> {
    if let Some(container) = re.captures_iter(cgroup).next() {
        return container.get(1).map(|m| m.as_str().to_string());
    }

    None
}

mod test {
    #[test]
    fn regex_can_match_docker() {
        use crate::aggregations::container::container_id;
        use crate::aggregations::container::DOCKER_PATTERN;

        let cgroup = r#"
10:cpuset:/docker/a844b8599d5e23c620c646b69c6d93c4014247cd0be9ec142c44219b6467e07f
9:net_cls,net_prio:/docker/a844b8599d5e23c620c646b69c6d93c4014247cd0be9ec142c44219b6467e07f
8:freezer:/docker/a844b8599d5e23c620c646b69c6d93c4014247cd0be9ec142c44219b6467e07f
7:devices:/docker/a844b8599d5e23c620c646b69c6d93c4014247cd0be9ec142c44219b6467e07f
6:memory:/docker/a844b8599d5e23c620c646b69c6d93c4014247cd0be9ec142c44219b6467e07f
5:rdma:/
4:pids:/docker/a844b8599d5e23c620c646b69c6d93c4014247cd0be9ec142c44219b6467e07f
3:cpu,cpuacct:/docker/a844b8599d5e23c620c646b69c6d93c4014247cd0be9ec142c44219b6467e07f
2:blkio:/docker/a844b8599d5e23c620c646b69c6d93c4014247cd0be9ec142c44219b6467e07f
1:name=systemd:/docker/a844b8599d5e23c620c646b69c6d93c4014247cd0be9ec142c44219b6467e07f
0::/system.slice/docker.service
"#;

        assert_eq!(
            container_id(&DOCKER_PATTERN, cgroup),
            Some("a844b8599d5e23c620c646b69c6d93c4014247cd0be9ec142c44219b6467e07f".to_string())
        );
    }

    #[test]
    fn regex_can_match_kube() {
        use crate::aggregations::container::container_id;
        use crate::aggregations::container::DOCKER_PATTERN;

        let cgroup = r#"
12:hugetlb:/kubepods/besteffort/poda21e738c-d6b6-11e8-82df-002590deaca4/a844b8599d5e23c620c646b69c6d93c4014247cd0be9ec142c44219b6467e07f

11:perf_event:/kubepods/besteffort/poda21e738c-d6b6-11e8-82df-002590deaca4/a844b8599d5e23c620c646b69c6d93c4014247cd0be9ec142c44219b6467e07f

10:blkio:/kubepods/besteffort/poda21e738c-d6b6-11e8-82df-002590deaca4/a844b8599d5e23c620c646b69c6d93c4014247cd0be9ec142c44219b6467e07f

9:freezer:/kubepods/besteffort/poda21e738c-d6b6-11e8-82df-002590deaca4/a844b8599d5e23c620c646b69c6d93c4014247cd0be9ec142c44219b6467e07f

8:cpu,cpuacct:/kubepods/besteffort/poda21e738c-d6b6-11e8-82df-002590deaca4/a844b8599d5e23c620c646b69c6d93c4014247cd0be9ec142c44219b6467e07f

7:cpuset:/kubepods/besteffort/poda21e738c-d6b6-11e8-82df-002590deaca4/a844b8599d5e23c620c646b69c6d93c4014247cd0be9ec142c44219b6467e07f

6:devices:/kubepods/besteffort/poda21e738c-d6b6-11e8-82df-002590deaca4/a844b8599d5e23c620c646b69c6d93c4014247cd0be9ec142c44219b6467e07f

5:pids:/kubepods/besteffort/poda21e738c-d6b6-11e8-82df-002590deaca4/a844b8599d5e23c620c646b69c6d93c4014247cd0be9ec142c44219b6467e07f

4:memory:/kubepods/besteffort/poda21e738c-d6b6-11e8-82df-002590deaca4/a844b8599d5e23c620c646b69c6d93c4014247cd0be9ec142c44219b6467e07f

3:net_cls,net_prio:/kubepods/besteffort/poda21e738c-d6b6-11e8-82df-002590deaca4/a844b8599d5e23c620c646b69c6d93c4014247cd0be9ec142c44219b6467e07f

2:rdma:/
1:name=systemd:/kubepods/besteffort/poda21e738c-d6b6-11e8-82df-002590deaca4/a844b8599d5e23c620c646b69c6d93c4014247cd0be9ec142c44219b6467e07f

"#;

        assert_eq!(
            container_id(&DOCKER_PATTERN, cgroup),
            Some("a844b8599d5e23c620c646b69c6d93c4014247cd0be9ec142c44219b6467e07f".to_string())
        );
    }

    #[test]
    fn regex_no_match_no_cgroup() {
        use crate::aggregations::container::container_id;
        use crate::aggregations::container::DOCKER_PATTERN;

        let cgroup = r#"
10:cpuset:/
9:net_cls,net_prio:/
8:freezer:/
7:devices:/
6:memory:/
5:rdma:/
4:pids:/
3:cpu,cpuacct:/
2:blkio:/
1:name=systemd:/
0::/
"#;

        assert_eq!(container_id(&DOCKER_PATTERN, cgroup), None);
    }

    #[test]
    fn regex_no_match_systemd() {
        use crate::aggregations::container::container_id;
        use crate::aggregations::container::DOCKER_PATTERN;

        let cgroup = r#"
10:cpuset:/
9:net_cls,net_prio:/
8:freezer:/
7:devices:/user.slice
6:memory:/user.slice/user-1000.slice/session-c1.scope
5:rdma:/
4:pids:/user.slice/user-1000.slice/session-c1.scope
3:cpu,cpuacct:/user.slice
2:blkio:/user.slice
1:name=systemd:/user.slice/user-1000.slice/session-c1.scope
0::/user.slice/user-1000.slice/session-c1.scope
"#;

        assert_eq!(container_id(&DOCKER_PATTERN, cgroup), None);
    }
}
