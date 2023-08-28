use crate::preview2::{StreamState, Table, TableError};
use cap_net_ext::{AddressFamily, Blocking, TcpListenerExt};
use cap_std::net::TcpListener;
use io_lifetimes::raw::{FromRawSocketlike, IntoRawSocketlike};
use std::io;
use std::sync::Arc;

use super::{HostInputStream, HostOutputStream, OutputStreamError};

/// The state of a TCP socket.
///
/// This represents the various states a socket can be in during the
/// activities of binding, listening, accepting, and connecting.
pub(crate) enum HostTcpState {
    /// The initial state for a newly-created socket.
    Default,

    /// Binding started via `start_bind`.
    BindStarted,

    /// Binding finished via `finish_bind`. The socket has an address but
    /// is not yet listening for connections.
    Bound,

    /// Listening started via `listen_start`.
    ListenStarted,

    /// The socket is now listening and waiting for an incoming connection.
    Listening,

    /// An outgoing connection is started via `start_connect`.
    Connecting,

    /// An outgoing connection is ready to be established.
    ConnectReady,

    /// An outgoing connection has been established.
    Connected,
}

/// A host TCP socket, plus associated bookkeeping.
///
/// The inner state is wrapped in an Arc because the same underlying socket is
/// used for implementing the stream types.
pub(crate) struct HostTcpSocket {
    /// The part of a `HostTcpSocket` which is reference-counted so that we
    /// can pass it to async tasks.
    pub(crate) inner: HostTcpSocketInner,

    /// The current state in the bind/listen/accept/connect progression.
    pub(crate) tcp_state: HostTcpState,
}

pub(crate) struct HostTcpSocketInner {
    stream: Arc<tokio::net::TcpStream>,
}

impl HostTcpSocketInner {
    fn new(stream: tokio::net::TcpStream) -> Self {
        Self {
            stream: Arc::new(stream),
        }
    }

    pub(crate) fn tcp_socket(&self) -> &tokio::net::TcpStream {
        &self.stream
    }

    pub(crate) fn clone(&self) -> Self {
        Self {
            stream: Arc::clone(&self.stream),
        }
    }
}

#[async_trait::async_trait]
impl HostInputStream for HostTcpSocketInner {
    fn read(&mut self, size: usize) -> Result<(bytes::Bytes, StreamState), anyhow::Error> {
        if size == 0 {
            return Ok((bytes::Bytes::new(), StreamState::Open));
        }

        let mut buf = bytes::BytesMut::with_capacity(size);
        let n = match self.stream.try_read_buf(&mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => 0,
            Err(_) => {
                // FIXME: this is a closed stream, but we need to record it for future calls to
                // ready
                return Ok((bytes::Bytes::new(), StreamState::Closed));
            }
        };

        buf.truncate(n);
        Ok((buf.freeze(), StreamState::Open))
    }

    async fn ready(&mut self) -> Result<(), anyhow::Error> {
        self.stream.readable().await?;
        Ok(())
    }
}

const SOCKET_READY_SIZE: usize = 1024 * 1024 * 1024;

#[async_trait::async_trait]
impl HostOutputStream for HostTcpSocketInner {
    fn write(&mut self, mut bytes: bytes::Bytes) -> Result<(), OutputStreamError> {
        todo!("HostOutputStream for HostTcpSocketInner is placeholder")
    }

    fn flush(&mut self) -> Result<(), OutputStreamError> {
        todo!("HostOutputStream for HostTcpSocketInner is placeholder")
    }

    async fn write_ready(&mut self) -> Result<usize, OutputStreamError> {
        todo!("HostOutputStream for HostTcpSocketInner is placeholder")
    }
}

impl HostTcpSocket {
    /// Create a new socket in the given family.
    pub fn new(family: AddressFamily) -> io::Result<Self> {
        // Create a new host socket and set it to non-blocking, which is needed
        // by our async implementation.
        let tcp_socket = TcpListener::new(family, Blocking::No)?;

        let tcp_socket = unsafe {
            tokio::net::TcpStream::try_from(std::net::TcpStream::from_raw_socketlike(
                tcp_socket.into_raw_socketlike(),
            ))
            .unwrap()
        };

        Ok(Self {
            inner: HostTcpSocketInner::new(tcp_socket),
            tcp_state: HostTcpState::Default,
        })
    }

    /// Create a `HostTcpSocket` from an existing socket.
    ///
    /// The socket must be in non-blocking mode.
    pub fn from_tcp_stream(tcp_socket: cap_std::net::TcpStream) -> io::Result<Self> {
        let fd = rustix::fd::OwnedFd::from(tcp_socket);
        let tcp_socket = TcpListener::from(fd);

        let tcp_socket = unsafe {
            tokio::net::TcpStream::try_from(std::net::TcpStream::from_raw_socketlike(
                tcp_socket.into_raw_socketlike(),
            ))
            .unwrap()
        };

        Ok(Self {
            inner: HostTcpSocketInner::new(tcp_socket),
            tcp_state: HostTcpState::Default,
        })
    }

    pub fn tcp_socket(&self) -> &tokio::net::TcpStream {
        self.inner.tcp_socket()
    }

    pub fn clone_inner(&self) -> HostTcpSocketInner {
        self.inner.clone()
    }
}

pub(crate) trait TableTcpSocketExt {
    fn push_tcp_socket(&mut self, tcp_socket: HostTcpSocket) -> Result<u32, TableError>;
    fn delete_tcp_socket(&mut self, fd: u32) -> Result<HostTcpSocket, TableError>;
    fn is_tcp_socket(&self, fd: u32) -> bool;
    fn get_tcp_socket(&self, fd: u32) -> Result<&HostTcpSocket, TableError>;
    fn get_tcp_socket_mut(&mut self, fd: u32) -> Result<&mut HostTcpSocket, TableError>;
}

impl TableTcpSocketExt for Table {
    fn push_tcp_socket(&mut self, tcp_socket: HostTcpSocket) -> Result<u32, TableError> {
        self.push(Box::new(tcp_socket))
    }
    fn delete_tcp_socket(&mut self, fd: u32) -> Result<HostTcpSocket, TableError> {
        self.delete(fd)
    }
    fn is_tcp_socket(&self, fd: u32) -> bool {
        self.is::<HostTcpSocket>(fd)
    }
    fn get_tcp_socket(&self, fd: u32) -> Result<&HostTcpSocket, TableError> {
        self.get(fd)
    }
    fn get_tcp_socket_mut(&mut self, fd: u32) -> Result<&mut HostTcpSocket, TableError> {
        self.get_mut(fd)
    }
}
