use super::scanner::ScanResult;
use crate::{errors::ScannerError, networking::icmp::Icmp};
use anyhow::Result;
use pnet::packet::{
    ethernet::EthernetPacket,
    icmp::{destination_unreachable::IcmpCodes, echo_reply, IcmpPacket, IcmpTypes},
    ipv4::Ipv4Packet,
    Packet,
};
use std::{net::IpAddr, time::Duration};

/// Scans a host using ICMP echo requests.
///
/// Determines if a host is up or down. Might not work behind a firewall.
pub fn icmp_scan(
    src_ip: IpAddr,
    _src_port: u16,
    dest_ip: IpAddr,
    _dest_port: u16,
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

    let icmp_codes = vec![
        IcmpCodes::DestinationProtocolUnreachable,
        IcmpCodes::DestinationHostUnreachable,
        IcmpCodes::DestinationPortUnreachable,
        IcmpCodes::NetworkAdministrativelyProhibited,
        IcmpCodes::HostAdministrativelyProhibited,
        IcmpCodes::CommunicationAdministrativelyProhibited,
    ];

    let (response, rtt) = Icmp::send_icmp_packet(ipv4_src, ipv4_dest, timeout)?;

    // No response -> Down.
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

    let icmp_type = icmp_packet.get_icmp_type();
    let icmp_code = icmp_packet.get_icmp_code();

    match (icmp_type, icmp_code) {
        // Unreachable -> Down.
        (IcmpTypes::DestinationUnreachable, code) if icmp_codes.contains(&code) => {
            Ok((ScanResult::Down, rtt))
        }
        // Echo reply -> Up.
        (IcmpTypes::EchoReply, echo_reply::IcmpCodes::NoCode) => Ok((ScanResult::Up, rtt)),
        // Unexpected response.
        _ => Err(ScannerError::UnexpectedIcmpResponse.into()),
    }
}
