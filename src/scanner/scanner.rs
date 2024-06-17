use std::{net::IpAddr, time::Duration};

use futures::future::join_all;

use crate::networking::socket_iterator;

use super::tcp_scan::tcp_syn_scan;

pub enum ScanMethod {
    Syn,
    Connect,
}

#[derive(Debug)]
pub enum ScanResult {
    Open,
    Closed,
    Filtered,
}

pub struct Scanner {
    pub method: ScanMethod,
    pub ip_addresses: Vec<IpAddr>,
    pub port_numbers: Vec<u16>,
    pub timeout: Duration,
}

impl Scanner {
    pub fn new(
        method: ScanMethod,
        ip_addresses: Vec<IpAddr>,
        port_numbers: Vec<u16>,
        timeout: Duration,
    ) -> Self {
        Self {
            method,
            ip_addresses,
            port_numbers,
            timeout,
        }
    }

    pub async fn scan(&self, src_ip: IpAddr, src_port: u16) {
        let sockets = socket_iterator::SocketIterator::new(&self.ip_addresses, &self.port_numbers);
        let scan_method = match self.method {
            ScanMethod::Syn => tcp_syn_scan,
            ScanMethod::Connect => todo!(),
        };
        let mut futures = Vec::new();
        for socket in sockets {
            let future = tokio::spawn(async move {
                let status = tokio::task::spawn_blocking(move || {
                    scan_method(src_ip, src_port, socket.ip(), socket.port(), socket.port())
                })
                .await
                .unwrap();
                (socket, status)
            });
            futures.push(future);
        }
        let results = join_all(futures).await;
        println!("{:?}", results);
    }
}
