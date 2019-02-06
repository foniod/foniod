use crate::backends::Message;

use epoll;

use std::io;
use std::os::unix::io::RawFd;

pub type EventCallback = Box<Fn(&[u8]) -> Option<Message> + Send>;

pub trait EventHandler {
    fn fd(&self) -> RawFd;
    fn poll(&self);
}

pub fn epoll_loop(events: Vec<Box<dyn EventHandler>>, timeout: i32) -> io::Result<()> {
    let efd = epoll::create(true)?;

    for eh in events.iter() {
        let fd = eh.fd();
        let hptr = eh as *const Box<dyn EventHandler> as u64;

        epoll::ctl(
            efd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            fd,
            epoll::Event::new(epoll::Events::EPOLLIN, hptr),
        )?;
    }

    let mut eventsbuf: Vec<epoll::Event> = events
        .iter()
        .map(|_| epoll::Event::new(epoll::Events::empty(), 0))
        .collect();

    loop {
        match epoll::wait(efd, timeout, eventsbuf.as_mut_slice()) {
            Err(err) => return Err(err),
            Ok(0) => continue,
            Ok(x) => for ev in eventsbuf[..x].iter() {
                let handler =
                    unsafe { (ev.data as *const Box<dyn EventHandler>).as_ref().unwrap() };
                handler.poll();
            },
        }
    }
}
