use super::tcp_scan::tcp_syn_scan;
use crate::{
    networking::socket_iterator,
    scanner::{
        icmp_scan::icmp_scan,
        tcp_scan::{
            tcp_ack_scan, tcp_connect_scan, tcp_fin_scan, tcp_maimon_scan, tcp_null_scan,
            tcp_window_scan, tcp_xmas_scan,
        },
    },
};
use futures::future::join_all;
use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

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
    Up,
    Down,
}

pub struct Scanner {}

impl Scanner {
    pub async fn scan(
        method: ScanMethod,
        src_ip: IpAddr,
        src_port: u16,
        ip_addresses: &Vec<IpAddr>,
        port_numbers: &Vec<u16>,
        timeout: Duration,
    ) {
        let sockets = socket_iterator::SocketIterator::new(ip_addresses, port_numbers);
        let scan_method = match method {
            ScanMethod::TcpSyn => tcp_syn_scan,
            ScanMethod::TcpConnect => tcp_connect_scan,
            ScanMethod::TcpAck => tcp_ack_scan,
            ScanMethod::TcpFin => tcp_fin_scan,
            ScanMethod::TcpXmas => tcp_xmas_scan,
            ScanMethod::TcpNull => tcp_null_scan,
            ScanMethod::TcpWindow => tcp_window_scan,
            ScanMethod::TcpMaimon => tcp_maimon_scan,
        };
        let mut handles = Vec::new();
        for socket in sockets {
            let handle = tokio::spawn(async move {
                let status = tokio::task::spawn_blocking(move || {
                    scan_method(src_ip, src_port, socket.ip(), socket.port(), timeout)
                })
                .await
                .unwrap();
                (socket, status)
            });
            handles.push(handle);
        }
        let results = join_all(handles).await;
        println!("{:?}", results);
    }

    pub async fn ping(src_ip: IpAddr, ip_addresses: Vec<IpAddr>, timeout: Duration) {
        let mut handles = Vec::new();
        for dest_ip in ip_addresses {
            let handle = tokio::spawn(async move {
                let status =
                    tokio::task::spawn_blocking(move || icmp_scan(src_ip, 0, dest_ip, 0, timeout))
                        .await
                        .unwrap();
                (dest_ip, status)
            });
            handles.push(handle);
        }
        let results = join_all(handles).await;
        println!("{:?}", results);
    }

    pub fn save_results() {
        todo!();
    }
}
