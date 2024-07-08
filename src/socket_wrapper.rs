use mio;
use tokio;
use std::{io::Read, os::fd::AsRawFd};

struct RawSocketMio {
    socket: socket2::Socket
}

impl RawSocketMio {
    fn new(domain: socket2::Domain, protocol: socket2::Protocol) -> tokio::io::Result<Self> {
        let socket = socket2::Socket::new(
            domain, 
            socket2::Type::RAW, 
            Some(protocol)).expect("Failed to create socket");
        socket.set_nonblocking(true)?;

        Ok(Self { socket: socket })
    }
    fn send_to(&self, buf: &[u8], addr: std::net::SocketAddr) -> tokio::io::Result<usize> {
        self.socket.send_to(buf, &addr.into())
    }
    fn recv(&self, buf: &mut [u8]) -> tokio::io::Result<usize> {
        (&self.socket).read(buf)
    }
    fn set_ttl(&self, ttl: u8) -> tokio::io::Result<()> {
        match self.socket.domain()? {
            socket2::Domain::IPV4 => self.socket.set_ttl(ttl as u32),
            socket2::Domain::IPV6 => self.socket.set_unicast_hops_v6(ttl as u32),
            _ => panic!("RawSocketMio: unsupported socket")
        }
        
    }
}

impl std::os::unix::io::AsRawFd for RawSocketMio {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        self.socket.as_raw_fd()
    }
}

impl mio::event::Source for RawSocketMio {
    fn register(&mut self, poll: &mio::Registry, token: mio::Token, interest: mio::Interest) -> tokio::io::Result<()> {
        mio::unix::SourceFd(&self.as_raw_fd()).register(poll, token, interest)
    }

    fn reregister(
        &mut self,
        poll: &mio::Registry,
        token: mio::Token,
        interest: mio::Interest,
    ) -> tokio::io::Result<()> {
        mio::unix::SourceFd(&self.as_raw_fd()).reregister(poll, token, interest)
    }

    fn deregister(&mut self, poll: &mio::Registry) -> tokio::io::Result<()> {
        mio::unix::SourceFd(&self.as_raw_fd()).deregister(poll)
    }
}

#[derive(Clone)]
pub struct RawSocketTokio {
    socket: std::sync::Arc<tokio::io::unix::AsyncFd<RawSocketMio>>,
}

impl RawSocketTokio {
    pub fn new(domain: socket2::Domain, protocol: socket2::Protocol) -> tokio::io::Result<Self> {
        let mio_socket = RawSocketMio::new(domain, protocol).expect("Failed to create RawSocketMio");
        let fd_mio_socket = tokio::io::unix::AsyncFd::new(mio_socket)?;
        Ok(Self {
            socket: std::sync::Arc::new(fd_mio_socket),
        })
    }
    pub async fn send_to(&self, buf: &[u8], addr: std::net::SocketAddr) -> tokio::io::Result<usize> {
        self.socket
            .async_io(tokio::io::Interest::WRITABLE, |socket| socket.send_to(buf, addr))
            .await
    }
    pub async fn recv(&self, buf: &mut [u8]) -> tokio::io::Result<usize> {
        self.socket
            .async_io(tokio::io::Interest::READABLE, |socket| socket.recv(buf))
            .await
    }
    pub fn set_ttl(&self, ttl: u8) -> tokio::io::Result<()> {
        self.socket.get_ref().set_ttl(ttl)
    }
}
