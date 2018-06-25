pub mod udp;
pub mod tcpv4;
use cadence::StatsdClient;
use redbpf::PerfMap;

pub trait Grain<T> where T: PerfReporter {
    fn start() -> T;
}

pub trait PerfReporter {
    fn perfmaps(&mut self, statsd: &StatsdClient) -> Vec<PerfMap>;
}
