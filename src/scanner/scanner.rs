use super::tcp_scan::tcp_syn_scan;
use crate::{
    networking::socket_iterator,
    scanner::tcp_scan::{
        tcp_ack_scan, tcp_connect_scan, tcp_fin_scan, tcp_maimon_scan, tcp_null_scan,
        tcp_window_scan, tcp_xmas_scan,
    },
};
use futures::future::join_all;
use std::{net::IpAddr, time::Duration};

pub enum ScanMethod {
    TcpSyn,
    TcpConnect,
    TcpAck,
    TcpFin,
    TcpXmas,
    TcpNull,
    TcpWindow,
    TcpMaimon,
}

#[derive(Debug)]
pub enum ScanResult {
    Open,
    Closed,
    Filtered,
    Unfiltered,
    OpenOrFiltered,
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

    pub async fn scan(&self, src_ip: IpAddr, src_port: u16, timeout: Duration) {
        let sockets = socket_iterator::SocketIterator::new(&self.ip_addresses, &self.port_numbers);
        let scan_method = match self.method {
            ScanMethod::TcpSyn => tcp_syn_scan,
            ScanMethod::TcpConnect => tcp_connect_scan,
            ScanMethod::TcpAck => tcp_ack_scan,
            ScanMethod::TcpFin => tcp_fin_scan,
            ScanMethod::TcpXmas => tcp_xmas_scan,
            ScanMethod::TcpNull => tcp_null_scan,
            ScanMethod::TcpWindow => tcp_window_scan,
            ScanMethod::TcpMaimon => tcp_maimon_scan,
        };
        let mut futures = Vec::new();
        for socket in sockets {
            let future = tokio::spawn(async move {
                let status = tokio::task::spawn_blocking(move || {
                    scan_method(src_ip, src_port, socket.ip(), socket.port(), timeout)
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

    pub async fn ping() {
        todo!();
    }

    pub fn save_results() {
        todo!();
    }
}
