use crate::backends::Message;
use crate::grains::protocol::*;
use crate::grains::EventCallback;

use futures::prelude::*;
use lazy_socket::raw::Socket;
use std::os::unix::io::{AsRawFd, RawFd};
use std::pin::Pin;
use std::slice;
use std::task::{Context, Poll};
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

use redbpf::PerfMap;

pub type GrainIo = AsyncFd<RawFd>;
pub type MessageStream = dyn Stream<Item = Vec<Message>> + Unpin;
pub type MessageStreams = Vec<Box<MessageStream>>;

pub struct PerfMessageStream {
    poll: GrainIo,
    map: PerfMap,
    name: String,
    callback: EventCallback,
}

impl PerfMessageStream {
    pub fn new(name: String, map: PerfMap, callback: EventCallback) -> Self {
        let poll = GrainIo::with_interest(map.fd, Interest::READABLE).unwrap();
        PerfMessageStream {
            poll,
            map,
            name,
            callback,
        }
    }

    fn read_messages(&mut self) -> Vec<Message> {
        use redbpf::Event;

        let mut ret = Vec::new();
        while let Some(ev) = self.map.read() {
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
                    if let Some(msg) = msg {
                        ret.push(msg);
                    }
                }
            };
        }

        ret
    }
}

impl Stream for PerfMessageStream {
    type Item = Vec<Message>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        if let Poll::Pending = self.poll.poll_read_ready(cx) {
            return Poll::Pending;
        }

        let messages = self.read_messages();
        if let Poll::Ready(Ok(mut readguard)) = self.poll.poll_read_ready(cx) {
            readguard.clear_ready();
        }

        return Poll::Ready(Some(messages));
    }
}

pub struct SocketMessageStream {
    poll: GrainIo,
    socket: Socket,
    callback: EventCallback,
}

impl SocketMessageStream {
    pub fn new(_name: &str, socket: Socket, callback: EventCallback) -> Self {
        let poll = GrainIo::with_interest(socket.as_raw_fd(), Interest::READABLE).unwrap();
        SocketMessageStream {
            poll,
            socket,
            callback,
        }
    }

    fn read_messages(&self) -> Vec<Message> {
        let mut buf = [0u8; 64 * 1024];
        let mut headbuf = [0u8; ETH_HLEN + 4];

        let mut ret = Vec::new();
        while self.socket.recv(&mut headbuf, 0x02 /* MSG_PEEK */).is_ok() {
            let plen = ip::packet_len(&headbuf);
            let read = self.socket.recv(&mut buf[..plen], 0).unwrap();
            if read <= ETH_HLEN {
                break;
            }
            if let Some(msg) = (self.callback)(&buf[..plen]) {
                ret.push(msg);
            }
        }

        ret
    }
}

impl Stream for SocketMessageStream {
    type Item = Vec<Message>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        if let Poll::Ready(Ok(mut readguard)) = self.poll.poll_read_ready(cx) {
            let messages = self.read_messages();

            readguard.clear_ready();
            return Poll::Ready(Some(messages));
        }

        Poll::Pending
    }
}
