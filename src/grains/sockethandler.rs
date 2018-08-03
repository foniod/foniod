use grains::send_to;
use grains::events::*;
use grains::protocol::*;
use backends::BackendHandler;

use lazy_socket::raw::Socket;

use std::os::unix::io::AsRawFd;
use std::os::unix::io::RawFd;

pub struct SocketHandler {
    pub socket: Socket,
    pub callback: EventCallback,
    pub backends: Vec<BackendHandler>,
}

impl EventHandler for SocketHandler {
    fn fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
    fn poll(&self) {
        let mut buf = [0u8; 64 * 1024];
        let mut headbuf = [0u8; ETH_HLEN + 4];

        while self.socket.recv(&mut headbuf, 0x02 /* MSG_PEEK */).is_ok() {
            let plen = ip::packet_len(&headbuf);
            let read = self.socket.recv(&mut buf[..plen], 0).unwrap();
            if read <= ETH_HLEN {
                return;
            }

            let msg = match read {
                0 => None,
                _ => (self.callback)(&buf[..plen]),
            };

            msg.and_then(|msg| Some(send_to(&self.backends, msg)));
        }
    }
}
