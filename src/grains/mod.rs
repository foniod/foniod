pub mod outbound_tcpv4;
use cadence::StatsdClient;

pub trait Grain {
    fn start(statsd: &StatsdClient);
}
