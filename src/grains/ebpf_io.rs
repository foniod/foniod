use crate::backends::Message;
use crate::grains::protocol::*;
use crate::grains::EventCallback;

use futures::{Async, Poll, Stream};
use lazy_socket::raw::Socket;
use mio::unix::EventedFd;
use mio::{Evented, PollOpt, Ready, Token};
use redbpf::PerfMap;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::slice;
use tokio::reactor::{Handle, PollEvented2};

pub struct GrainIo(RawFd);

impl Evented for GrainIo {
    fn register(
        &self,
        poll: &mio::Poll,
        token: Token,
        interest: Ready,
        opts: PollOpt,
    ) -> io::Result<()> {
        EventedFd(&self.0).register(poll, token, interest, opts)
    }

    fn reregister(
        &self,
        poll: &mio::Poll,
        token: Token,
        interest: Ready,
        opts: PollOpt,
    ) -> io::Result<()> {
        EventedFd(&self.0).reregister(poll, token, interest, opts)
    }

    fn deregister(&self, poll: &mio::Poll) -> io::Result<()> {
        EventedFd(&self.0).deregister(poll)
    }
}

pub type MessageStream = dyn Stream<Item = Vec<Message>, Error = io::Error>;
pub type MessageStreams = Vec<Box<MessageStream>>;

pub struct PerfMessageStream {
    poll: PollEvented2<GrainIo>,
    map: PerfMap,
    name: String,
    callback: EventCallback,
}

impl PerfMessageStream {
    pub fn new(name: String, map: PerfMap, callback: EventCallback) -> Self {
        let io = GrainIo(map.fd);
        let poll = PollEvented2::new_with_handle(io, &Handle::default()).unwrap();
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
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        let ready = Ready::readable();
        if self.poll.poll_read_ready(ready)? == Async::NotReady {
            return Ok(Async::NotReady);
        }

        let messages = self.read_messages();
        self.poll.clear_read_ready(ready).unwrap();
        Ok(Async::Ready(Some(messages)))
    }
}

pub struct SocketMessageStream {
    poll: PollEvented2<GrainIo>,
    socket: Socket,
    callback: EventCallback,
}

impl SocketMessageStream {
    pub fn new(_name: &str, socket: Socket, callback: EventCallback) -> Self {
        let io = GrainIo(socket.as_raw_fd());
        let poll = PollEvented2::new_with_handle(io, &Handle::default()).unwrap();
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
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        let ready = Ready::readable();
        if self.poll.poll_read_ready(ready)? == Async::NotReady {
            return Ok(Async::NotReady);
        }

        let messages = self.read_messages();
        self.poll.clear_read_ready(ready).unwrap();
        Ok(Async::Ready(Some(messages)))
    }
}
