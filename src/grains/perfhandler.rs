use backends::BackendHandler;
use grains::events::*;
use grains::send_to;

use redbpf::PerfMap;

use std::os::unix::io::RawFd;
use std::slice;

pub struct PerfHandler {
    pub name: String,
    pub perfmap: PerfMap,
    pub callback: EventCallback,
    pub backends: Vec<BackendHandler>,
}

impl EventHandler for PerfHandler {
    fn fd(&self) -> RawFd {
        self.perfmap.fd
    }
    fn poll(&self) {
        use redbpf::Event;

        while let Some(ev) = self.perfmap.read() {
            match ev {
                Event::Lost(lost) => {
                    warn!("Possibly lost {} samples for {}", lost.count, &self.name);
                }
                Event::Sample(sample) => {
                    let msg = unsafe {
                        (self.callback)(slice::from_raw_parts(
                            sample.data.as_ptr(),
                            sample.size as usize,
                        ))
                    };
                    msg.and_then(|m| Some(send_to(&self.backends, m)));
                }
            }
        }
    }
}
