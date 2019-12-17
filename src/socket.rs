use pppoe_sys::{control, pppoe};

use std::io::{self, Read, Write};
use std::os::unix::io::{FromRawFd, RawFd};
use std::{fs, mem};

#[cfg(feature = "async")]
use mio::{event::Evented, unix::EventedFd, Poll, PollOpt, Ready, Token};

#[derive(Debug)]
pub struct Socket {
    connection: pppoe::Connection,
}

fn set_nonblock(fd: libc::c_int) -> io::Result<()> {
    crate::c_call_with_os_error(|| unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK)
    })
}

// TODO: Check std::net Sockets methods and impl them for this if applicable
impl Socket {
    pub fn on_interface(interface_name: &str) -> io::Result<Self> {
        control::init()?;

        let mut connection = pppoe::Connection::new();
        connection.set_interface_name(interface_name)?;
        pppoe::connection_data_init(&mut connection, None)?;

        #[cfg(feature = "async")]
        set_nonblock(connection.raw_socket())?;

        Ok(Socket { connection })
    }

    fn raw_socket(&self) -> RawFd {
        self.connection.raw_socket()
    }

    pub fn mac_address(&self) -> [u8; 6] {
        self.connection.mac_address()
    }

    pub fn set_nonblock(&self) -> io::Result<()> {
        set_nonblock(self.raw_socket())
    }

    pub fn send(&self, buffer: &[u8]) -> io::Result<usize> {
        let mut fd = unsafe { fs::File::from_raw_fd(self.raw_socket()) };
        let ret = fd.write(buffer);
        mem::forget(fd);
        ret
    }

    pub fn recv(&self, buffer: &mut [u8]) -> io::Result<usize> {
        let mut fd = unsafe { fs::File::from_raw_fd(self.raw_socket()) };
        let ret = fd.read(buffer);
        mem::forget(fd);
        ret
    }
}

#[cfg(feature = "async")]
impl Evented for Socket {
    fn register(
        &self,
        poll: &Poll,
        token: Token,
        interest: Ready,
        opts: PollOpt,
    ) -> io::Result<()> {
        EventedFd(&self.raw_socket()).register(poll, token, interest, opts)
    }

    fn reregister(
        &self,
        poll: &Poll,
        token: Token,
        interest: Ready,
        opts: PollOpt,
    ) -> io::Result<()> {
        EventedFd(&self.raw_socket()).reregister(poll, token, interest, opts)
    }

    fn deregister(&self, poll: &Poll) -> io::Result<()> {
        EventedFd(&self.raw_socket()).deregister(poll)
    }
}
