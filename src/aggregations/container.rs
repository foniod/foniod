use actix::fut::wrap_future;
use actix::prelude::*;
use actix::AsyncContext;
use bollard::{
    container::ListContainersOptions,
    system::{EventsOptions, EventsResults},
    Docker,
};
use chrono::{Duration, Utc};
use failure::{format_err, Error};
use futures::prelude::*;
use k8s_openapi::api::core::v1::Pod;
use kube::{
    api::{Api, ListParams, Meta, WatchEvent},
    Client,
};
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::str::FromStr;
use std::sync::{Arc, RwLock};

use crate::backends::Message;
use crate::metrics::Measurement;

#[derive(Copy, Clone, Serialize, Deserialize, Debug)]
pub enum ContainerSystem {
    Unset,
    Kubernetes,
    Docker,
}

fn default_system() -> ContainerSystem {
    ContainerSystem::Unset
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ContainerConfig {
    #[serde(default = "default_system")]
    system: ContainerSystem,
}
pub struct Container {
    config: ContainerConfig,
    upstream: Recipient<Message>,
    state: Arc<RwLock<State>>,
}

struct State {
    pods: HashMap<(Option<String>, String), Pod>,
    containers: HashMap<String, ContainerInfo>,
}

impl State {
    fn new() -> Self {
        Self {
            pods: HashMap::new(),
            containers: HashMap::new(),
        }
    }
}

impl Container {
    pub fn launch(config: ContainerConfig, upstream: Recipient<Message>) -> Recipient<Message> {
        Container {
            config,
            upstream,
            state: Arc::new(RwLock::new(State::new())),
        }
        .start()
        .recipient()
    }

    fn watch_kubernetes(&mut self, ctx: &mut <Self as Actor>::Context) {
        let fut = wrap_future::<_, Self>(async {
            let client = Client::try_default().await?;
            let pods: Api<Pod> = Api::all(client);
            let lp = ListParams::default();
            let stream = pods.watch(&lp, "0").await?.boxed();
            Ok::<_, kube::Error>(stream)
        });
        ctx.spawn(fut.map(|stream, _actor, ctx| match stream {
            Ok(stream) => {
                ctx.add_stream(stream);
            }
            Err(e) => {
                panic!("error retrieving kubernetes pods: {}", e);
            }
        }));
    }

    fn watch_docker(&mut self, ctx: &mut <Self as Actor>::Context) {
        let docker = Docker::connect_with_unix_defaults()
            .or_else(|_| Docker::connect_with_http_defaults())
            .expect("couldn't connect to docker daemon");

        let start = Utc::now();

        let client = docker.clone();
        let fut = wrap_future::<_, Self>(async move {
            let options = Some(ListContainersOptions::<String> {
                all: true,
                ..Default::default()
            });
            client.list_containers(options).await
        });

        let client = docker.clone();
        ctx.spawn(fut.map(move |containers, actor, ctx| match containers {
            Ok(containers) => {
                let mut state = actor.state.write().unwrap();
                for container in containers {
                    let mut info = ContainerInfo::new();
                    info.names.extend(container.names.iter().cloned());
                    state.containers.insert(container.id.clone(), info);
                }

                let mut filters = HashMap::new();
                filters.insert("type".to_string(), vec!["container".to_string()]);
                let options = EventsOptions::<String> {
                    since: start,
                    until: Utc::now() + Duration::weeks(52 * 100),
                    filters,
                };
                let events = client.events(Some(options));
                ctx.add_stream(events);
            }
            Err(e) => {
                panic!("error retrieving docker containers: {}", e);
            }
        }));
    }
}

impl Actor for Container {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        use ContainerSystem::*;
        match self.config.system {
            Unset => (),
            Kubernetes => self.watch_kubernetes(ctx),
            Docker => self.watch_docker(ctx),
        };
    }
}

impl Handler<Message> for Container {
    type Result = ();

    fn handle(&mut self, mut msg: Message, _ctx: &mut Context<Self>) -> Self::Result {
        let system = self.config.system;
        let state = self.state.clone();
        match msg {
            Message::List(ref mut ms) => ms
                .par_iter_mut()
                .for_each(move |m| add_tags(system, state.clone(), m)),
            Message::Single(ref mut m) => add_tags(system, state, m),
        }

        self.upstream.do_send(msg).unwrap();
    }
}

impl StreamHandler<Result<WatchEvent<Pod>, kube::Error>> for Container {
    fn handle(&mut self, event: Result<WatchEvent<Pod>, kube::Error>, _ctx: &mut Context<Self>) {
        let event = match event {
            Ok(e) => e,
            Err(e) => {
                error!("error watching kubernetes pods: {}", e);
                return;
            }
        };

        let mut state = self.state.write().unwrap();
        let key = |pod| (Meta::namespace(pod), Meta::name(pod));
        match event {
            WatchEvent::Added(pod) => {
                let name = Meta::name(&pod);
                debug!("added pod {}", name);
                state.pods.insert(key(&pod), pod.clone());
            }
            WatchEvent::Modified(pod) => {
                let name = Meta::name(&pod);
                debug!("modified pod: {}", name);
                state.pods.insert(key(&pod), pod.clone()).unwrap();
            }
            WatchEvent::Deleted(pod) => {
                let name = Meta::name(&pod);
                debug!("deleted pod: {}", name);
                state.pods.remove(&key(&pod)).unwrap();
            }
            WatchEvent::Bookmark(_pod) => {}
            WatchEvent::Error(e) => println!("pod error: {}", e),
        }
    }
}

impl StreamHandler<Result<EventsResults, bollard::errors::Error>> for Container {
    fn handle(
        &mut self,
        event: Result<EventsResults, bollard::errors::Error>,
        _ctx: &mut Context<Self>,
    ) {
        let event = match event {
            Ok(e) => e,
            Err(e) => {
                error!("error watching docker events: {}", e);
                return;
            }
        };

        assert!(event.type_ == "container");

        let mut state = self.state.write().unwrap();
        let containers = &mut state.containers;
        let id = event.actor.id.clone();
        let attrs = &event.actor.attributes;

        match event.action.as_str() {
            "create" => {
                let mut info = ContainerInfo::new();
                info.names.insert(attrs.get("name").unwrap().clone());
                containers.insert(id, info);
            }
            "rename" => {
                let info = containers.entry(id).or_insert_with(|| {
                    warn!("received update container event for unknown container");
                    ContainerInfo::new()
                });
                if let Some(name) = attrs.get("oldName") {
                    info.names.remove(name);
                    info.names.insert(attrs.get("name").unwrap().clone());
                }
            }
            "destroy" => {
                containers.remove(&id);
            }
            _ => (),
        };
    }
}

fn pod_from_container_id<'a>(
    containers: &'a HashMap<(Option<String>, String), Pod>,
    id: &str,
) -> Option<&'a Pod> {
    containers.values().find(|pod| {
        if let Some(status) = &pod.status {
            if let Some(statuses) = &status.container_statuses {
                return statuses
                    .iter()
                    .find(|status| {
                        if let Some(c_id) = &status.container_id {
                            return &c_id["docker://".len()..] == id;
                        }
                        false
                    })
                    .is_some();
            }
        }
        false
    })
}

fn container_name_from_container_id<'a>(
    containers: &'a HashMap<String, ContainerInfo>,
    id: &str,
) -> Option<&'a String> {
    containers.get(id).and_then(|info| info.names.iter().next())
}

#[derive(Debug)]
struct ContainerInfo {
    names: HashSet<String>,
}

impl ContainerInfo {
    fn new() -> Self {
        Self {
            names: HashSet::new(),
        }
    }
}

fn add_tags(system: ContainerSystem, state: Arc<RwLock<State>>, msg: &mut Measurement) {
    if let Ok(id) = container_id_from_measurement(msg) {
        let state = state.read().unwrap();
        use ContainerSystem::*;
        match system {
            Unset => (),
            Kubernetes => match pod_from_container_id(&state.pods, &id) {
                Some(pod) => {
                    msg.tags.insert("kubernetes_pod_name", Meta::name(pod));
                    if let Some(n) = Meta::namespace(pod) {
                        msg.tags.insert("kubernetes_namespace", n);
                    }
                }
                None => warn!("couldn't find kube pod for container {}", id),
            },
            Docker => match container_name_from_container_id(&state.containers, &id) {
                Some(name) => msg.tags.insert("docker_name", name.clone()),
                None => warn!("couldn't find docker name for container {}", id),
            },
        }

        msg.tags.insert("docker_id", id);
    }
}

#[inline]
fn container_id_from_measurement(msg: &Measurement) -> Result<String, Error> {
    let pid_str = msg
        .tags
        .get("process_id")
        .ok_or_else(|| format_err!("No pid"))?;
    let pid = u32::from_str(&pid_str)?;

    let cgroup = fs::read_to_string(format!("/proc/{}/cgroup", pid))
        .or_else(|_| fs::read_to_string(format!("/proc/{}/cgroup", pid)))?;

    container_id(&cgroup).ok_or_else(|| format_err!("No container"))
}

#[inline]
fn container_id(cgroup: &str) -> Option<String> {
    for line in cgroup.lines() {
        let path = line.split(":").last()?;
        if !path.starts_with("/docker") && !path.starts_with("/kube") {
            continue;
        }

        return Some(path[path.rfind("/").unwrap() + 1..].to_string());
    }

    None
}

mod test {
    #[test]
    fn regex_can_match_docker() {
        use crate::aggregations::container::container_id;

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
            container_id(cgroup),
            Some("a844b8599d5e23c620c646b69c6d93c4014247cd0be9ec142c44219b6467e07f".to_string())
        );
    }

    #[test]
    fn regex_can_match_kube() {
        use crate::aggregations::container::container_id;

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
            container_id(cgroup),
            Some("a844b8599d5e23c620c646b69c6d93c4014247cd0be9ec142c44219b6467e07f".to_string())
        );
    }

    #[test]
    fn regex_no_match_no_cgroup() {
        use crate::aggregations::container::container_id;

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

        assert_eq!(container_id(cgroup), None);
    }

    #[test]
    fn regex_no_match_systemd() {
        use crate::aggregations::container::container_id;

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

        assert_eq!(container_id(cgroup), None);
    }
}
