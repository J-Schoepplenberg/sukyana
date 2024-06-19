use super::scanner::ScanResult;
use crate::{errors::ScannerError, networking::udp::Udp};
use anyhow::Result;
use pnet::packet::{
    ethernet::EthernetPacket,
    icmp::{destination_unreachable::IcmpCodes, IcmpPacket},
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    Packet,
};
use std::{net::IpAddr, time::Duration};

/// Scans a host using UDP packets. Determines if a port is open, closed, or filtered.
/// 
/// Most popular services run over TCP, but UDP is used for services like DNS, DHCP, and SNMP.
pub fn udp_scan(
    src_ip: IpAddr,
    src_port: u16,
    dest_ip: IpAddr,
    dest_port: u16,
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

    let (response, rtt) = Udp::send_udp_packet(ipv4_src, src_port, ipv4_dest, dest_port, timeout)?;

    // No response -> open or filtered.
    let packet = match response {
        Some(packet) => packet,
        None => return Ok((ScanResult::OpenOrFiltered, rtt)),
    };

    let ethernet_packet =
        EthernetPacket::new(&packet).ok_or(ScannerError::CantCreateEthernetPacket)?;

    let ipv4_packet =
        Ipv4Packet::new(ethernet_packet.payload()).ok_or(ScannerError::CantCreateIpv4Packet)?;

    match ipv4_packet.get_next_level_protocol() {
        // Any response -> open.
        IpNextHeaderProtocols::Udp => return Ok((ScanResult::Open, rtt)),
        IpNextHeaderProtocols::Icmp => {
            let icmp_packet =
                IcmpPacket::new(ipv4_packet.payload()).ok_or(ScannerError::CantCreateIcmpPacket)?;
            let codes_1 = &[IcmpCodes::DestinationPortUnreachable];
            let codes_2 = &[
                IcmpCodes::DestinationHostUnreachable,
                IcmpCodes::DestinationProtocolUnreachable,
                IcmpCodes::NetworkAdministrativelyProhibited,
                IcmpCodes::HostAdministrativelyProhibited,
                IcmpCodes::CommunicationAdministrativelyProhibited,
            ];
            let icmp_code = icmp_packet.get_icmp_code();
            match icmp_code {
                // ICMP port unreachable -> closed.
                code if codes_1.contains(&code) => return Ok((ScanResult::Closed, rtt)),
                // Other ICMP unreachable errors -> filtered.
                code if codes_2.contains(&code) => return Ok((ScanResult::Filtered, rtt)),
                // Unexpected ICMP response.
                _ => return Err(ScannerError::UnexpectedIcmpResponse.into()),
            }
        }
        // Unexpected UDP response.
        _ => return Err(ScannerError::UnexpectedUdpResponse.into()),
    }
}
