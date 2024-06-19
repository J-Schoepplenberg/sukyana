use super::scanner::ScanResult;
use crate::{errors::ScannerError, networking::udp::Udp};
use anyhow::Result;
use pnet::packet::{ethernet::EthernetPacket, icmp::IcmpPacket, ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, Packet};
use std::{net::IpAddr, time::Duration};

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
        }
        _ => return Err(ScannerError::UnexpectedUdpResponse.into()),
    }
    todo!()
}
