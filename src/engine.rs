use std::{io, net::SocketAddr, time::Duration};
use tokio::{net::TcpStream, time::timeout};
mod socket_iterator;

#[derive(Debug)]
pub struct Engine {
    pub timeout: Duration,
}

impl Engine {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_millis(200),
        }
    }

    /// Attempts to connect to the socket with a specified timeout.
    ///
    /// If the future (`TcpStream`) does not complete before the timeout duration, an error is returned.
    pub async fn connect(&self, socket: SocketAddr) -> io::Result<TcpStream> {
        timeout(
            self.timeout,
            async move { TcpStream::connect(socket).await },
        )
        .await?
    }
}
