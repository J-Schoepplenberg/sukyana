use super::scanner::ScanResult;
use crate::{
    errors::ScannerError,
    networking::{icmp::Icmp, interface::Interface},
};
use anyhow::Result;
use pnet::packet::{
    ethernet::EthernetPacket,
    icmp::{destination_unreachable::IcmpCodes, echo_reply, IcmpPacket, IcmpTypes},
    ipv4::Ipv4Packet,
    Packet,
};
use std::{net::IpAddr, time::Duration};

/// Scans a host using ICMP echo requests. Also known as a ping scan.
///
/// Determines if a host is up or down. Might not work behind a firewall.
pub fn icmp_scan(
    interface: Interface,
    src_ip: IpAddr,
    dest_ip: IpAddr,
    timeout: Duration,
) -> Result<(ScanResult, Duration)> {
    let ipv4_src = match src_ip {
        IpAddr::V4(ip) => ip,
        _ => Err(ScannerError::UnsupportedIpVersion)?,
    };

    let ipv4_dest = match dest_ip {
        IpAddr::V4(ip) => ip,
        _ => Err(ScannerError::UnsupportedIpVersion)?,
    };

    let (response, rtt) = Icmp::send_icmp_packet(interface, ipv4_src, ipv4_dest, timeout)?;

    // No response -> down.
    let packet = match response {
        Some(packet) => packet,
        None => return Ok((ScanResult::Down, rtt)),
    };

    let ethernet_packet =
        EthernetPacket::new(&packet).ok_or(ScannerError::CantCreateEthernetPacket)?;

    let ipv4_packet =
        Ipv4Packet::new(ethernet_packet.payload()).ok_or(ScannerError::CantCreateIpv4Packet)?;

    let icmp_packet =
        IcmpPacket::new(ipv4_packet.payload()).ok_or(ScannerError::CantCreateIcmpPacket)?;

    let icmp_codes = vec![
        IcmpCodes::DestinationProtocolUnreachable,
        IcmpCodes::DestinationHostUnreachable,
        IcmpCodes::DestinationPortUnreachable,
        IcmpCodes::NetworkAdministrativelyProhibited,
        IcmpCodes::HostAdministrativelyProhibited,
        IcmpCodes::CommunicationAdministrativelyProhibited,
    ];

    let icmp_type = icmp_packet.get_icmp_type();
    let icmp_code = icmp_packet.get_icmp_code();

    match (icmp_type, icmp_code) {
        // Unreachable -> down.
        (IcmpTypes::DestinationUnreachable, code) if icmp_codes.contains(&code) => {
            Ok((ScanResult::Down, rtt))
        }
        // Echo reply -> up.
        (IcmpTypes::EchoReply, echo_reply::IcmpCodes::NoCode) => Ok((ScanResult::Up, rtt)),
        // Unexpected response.
        _ => Err(ScannerError::UnexpectedIcmpResponse.into()),
    }
}
