use crate::{errors::ScannerError, networking::arp::Arp};
use anyhow::Result;
use pnet::util::MacAddr;
use std::{net::IpAddr, time::Duration};

/// Sends ARP packets to determine the MAC addresses of hosts on the local network.
/// 
/// Only hosts that are online will respond to ARP requests.
pub fn arp_scan(
    src_ip: IpAddr,
    dest_ip: IpAddr,
    timeout: Duration,
) -> Result<(Option<MacAddr>, Duration)> {
    let ipv4_src = match src_ip {
        IpAddr::V4(ip) => ip,
        _ => Err(ScannerError::UnsupportedIpVersion)?,
    };

    let ipv4_dest = match dest_ip {
        IpAddr::V4(ip) => ip,
        _ => Err(ScannerError::UnsupportedIpVersion)?,
    };

    let (response, rtt) = Arp::send_request(ipv4_src, ipv4_dest, timeout)?;

    Ok((response, rtt))
}
