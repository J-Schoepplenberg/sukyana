use super::tcp_scan::tcp_syn_scan;
use crate::{
    networking::{interface::Interface, socket_iterator},
    scanner::{
        arp_scan::arp_scan,
        icmp_scan::icmp_scan,
        tcp_scan::{
            tcp_ack_scan, tcp_connect_scan, tcp_fin_scan, tcp_maimon_scan, tcp_null_scan,
            tcp_window_scan, tcp_xmas_scan,
        },
        udp_scan::udp_scan,
    },
};
use futures::future::join_all;
use log::info;
use pnet::util::MacAddr;
use std::{
    net::{IpAddr, SocketAddr},
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
    Udp,
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

pub struct Scanner;

impl Scanner {
    pub async fn scan(
        interface: Interface,
        method: ScanMethod,
        src_ip: IpAddr,
        src_port: u16,
        ip_addresses: &[IpAddr],
        port_numbers: &[u16],
        timeout: Duration,
    ) -> Vec<(SocketAddr, ScanResult, Duration)> {
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
            ScanMethod::Udp => udp_scan,
        };
        let mut handles = Vec::new();
        let mut total_sockets = 0;
        for socket in sockets {
            let handle = tokio::spawn(async move {
                let status = tokio::task::spawn_blocking(move || {
                    scan_method(
                        interface,
                        src_ip,
                        src_port,
                        socket.ip(),
                        socket.port(),
                        timeout,
                    )
                })
                .await
                .unwrap();
                (socket, status)
            });
            handles.push(handle);
            total_sockets += 1;
        }
        let results = join_all(handles).await;

        let mut scanned_sockets = Vec::new();
        let mut unreachable = 0;
        let mut responses = 0;

        for result in results {
            match result {
                Ok((dest_ip, Ok((status, rtt)))) => {
                    scanned_sockets.push((dest_ip, status, rtt));
                    responses += 1;
                }
                _ => {
                    unreachable += 1;
                }
            }
        }

        info!("{} sockets have been scanned.", responses);

        info!(
            "{} of {} sockets ran on an error.",
            unreachable, total_sockets
        );

        scanned_sockets
    }

    pub async fn ping(
        interface: Interface,
        src_ip: IpAddr,
        ip_addresses: Vec<IpAddr>,
        timeout: Duration,
    ) -> Vec<(IpAddr, ScanResult, Duration)> {
        let total_hosts = ip_addresses.len();

        let handles: Vec<_> = ip_addresses
            .into_iter()
            .map(|dest_ip| {
                tokio::spawn(async move {
                    let status = tokio::task::spawn_blocking(move || {
                        icmp_scan(interface, src_ip, dest_ip, timeout)
                    })
                    .await
                    .unwrap();
                    (dest_ip, status)
                })
            })
            .collect();

        let results = join_all(handles).await;

        let mut hosts = Vec::new();
        let mut unreachable = 0;
        let mut responses = 0;

        for result in results {
            match result {
                Ok((dest_ip, Ok((status, rtt)))) => {
                    hosts.push((dest_ip, status, rtt));
                    responses += 1;
                }
                _ => {
                    unreachable += 1;
                }
            }
        }

        info!(
            "{} hosts answered to your ping with an ICMP response.",
            responses
        );

        info!(
            "{} of {} IP addresses unreachable.",
            unreachable, total_hosts
        );

        hosts
    }

    /// Scans the local network with ARP requests.
    ///
    /// Returns IP addresses, MAC addresses, and round-trip times of hosts that responded.
    pub async fn arp(
        interface: Interface,
        src_ip: IpAddr,
        ip_addresses: Vec<IpAddr>,
        timeout: Duration,
    ) -> Vec<(IpAddr, MacAddr, Duration)> {
        let total_hosts = ip_addresses.len();

        let handles: Vec<_> = ip_addresses
            .into_iter()
            .map(|dest_ip| {
                tokio::spawn(async move {
                    let status = tokio::task::spawn_blocking(move || {
                        arp_scan(interface, src_ip, dest_ip, timeout)
                    })
                    .await
                    .unwrap();
                    (dest_ip, status)
                })
            })
            .collect();

        let results = join_all(handles).await;

        let mut hosts = Vec::new();
        let mut unreachable = 0;
        let mut responses = 0;

        for result in results {
            match result {
                Ok((dest_ip, Ok((Some(mac), rtt)))) => {
                    responses += 1;
                    hosts.push((dest_ip, mac, rtt));
                }
                _ => {
                    unreachable += 1;
                }
            }
        }

        info!(
            "{} hosts in your local network answered with an ARP response.",
            responses
        );
        info!(
            "{} of {} IP addresses unreachable.",
            unreachable, total_hosts
        );

        hosts
    }
}
