use super::tcp_scan::tcp_syn_scan;
use crate::{
    networking::{interface::Interface, socket_iterator::SocketIterator},
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
use futures::{stream::FuturesUnordered, StreamExt};
use log::info;
use pnet::util::MacAddr;
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

#[derive(Debug)]
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
    /// Scans the given IP addresses and port numbers with the specified scan method.
    ///
    /// Returns IP addresses, scan results, and round-trip times of hosts that responded.
    pub async fn scan(
        interface: Interface,
        method: ScanMethod,
        src_ip: IpAddr,
        src_port: u16,
        ip_addresses: &[IpAddr],
        port_numbers: &[u16],
        timeout: Duration,
    ) -> Vec<(SocketAddr, ScanResult, Duration)> {
        let total_sockets = ip_addresses.len() * port_numbers.len();

        let sockets = SocketIterator::new(ip_addresses, port_numbers);

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

        // Set of futures that complete in any order.
        // See: https://github.com/tokio-rs/tokio/issues/5564 -> faster than tokio's JoinSet.
        let mut futures = FuturesUnordered::new();

        sockets.for_each(|socket| {
            // Run the scan for each socket in a separate blocking thread.
            // This is a limitation introduced by the pnet crate, which does not support async.
            futures.push(tokio::task::spawn_blocking(move || {
                scan_method(
                    interface,
                    src_ip,
                    src_port,
                    socket.ip(),
                    socket.port(),
                    timeout,
                )
                .map(|scan| (socket, scan))
            }));
        });

        let mut scanned_sockets = Vec::new();
        let mut unreachable = 0;
        let mut responses = 0;

        while let Some(result) = futures.next().await {
            match result {
                Ok(Ok((socket, (scan, rtt)))) => {
                    scanned_sockets.push((socket, scan, rtt));
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

    /// Sends ICMP echo requests to the given IP addresses.
    ///
    /// Returns IP addresses, scan results, and round-trip times of hosts that responded.
    pub async fn ping(
        interface: Interface,
        src_ip: IpAddr,
        ip_addresses: Vec<IpAddr>,
        timeout: Duration,
    ) -> Vec<(IpAddr, ScanResult, Duration)> {
        let total_hosts = ip_addresses.len();

        let mut hosts = Vec::new();
        let mut unreachable = 0;
        let mut responses = 0;

        let mut futures = FuturesUnordered::new();

        ip_addresses.into_iter().for_each(|dest_ip| {
            futures.push(tokio::task::spawn_blocking(move || {
                icmp_scan(interface, src_ip, dest_ip, timeout).map(|scan| (dest_ip, scan))
            }));
        });

        while let Some(result) = futures.next().await {
            match result {
                Ok(Ok((dest_ip, (scan, rtt)))) => {
                    hosts.push((dest_ip, scan, rtt));
                    responses += 1;
                }
                _ => {
                    unreachable += 1;
                }
            }
        }

        info!("{} hosts have been sent an ICMP echo request.", responses);

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

        let mut hosts = Vec::new();
        let mut unreachable = 0;
        let mut responses = 0;

        let mut futures = FuturesUnordered::new();

        ip_addresses.into_iter().for_each(|dest_ip| {
            futures.push(tokio::task::spawn_blocking(move || {
                arp_scan(interface, src_ip, dest_ip, timeout).map(|scan| (dest_ip, scan))
            }));
        });

        while let Some(result) = futures.next().await {
            match result {
                Ok(Ok((dest_ip, (Some(mac), rtt)))) => {
                    hosts.push((dest_ip, mac, rtt));
                    responses += 1;
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
