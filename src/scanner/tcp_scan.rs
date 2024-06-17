use super::scanner::ScanResult;
use crate::{errors::CantFindRouterAddress, networking::tcp::Tcp};
use anyhow::Result;
use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    tcp::{TcpFlags, TcpPacket},
    Packet,
};
use std::net::IpAddr;

const TCP_FLAGS_RST_MASK: u8 = 0b00000100;

pub fn tcp_syn_scan(
    src_ip: IpAddr,
    src_port: u16,
    dest_ip: IpAddr,
    dest_port: u16,
    value: u16,
) -> Result<ScanResult> {
    let ipv4_src = match src_ip {
        IpAddr::V4(ip) => ip,
        _ => panic!("Only IPv4 is supported"),
    };
    let ipv4_dest = match dest_ip {
        IpAddr::V4(ip) => ip,
        _ => panic!("Only IPv4 is supported"),
    };
    let (response, rtt) = Tcp::send_syn_packet(value, ipv4_src, src_port, ipv4_dest, dest_port)?;

    let packet = match response {
        Some(packet) => packet,
        None => return Ok(ScanResult::Filtered),
    };

    let ethernet_packet = EthernetPacket::new(&packet).ok_or(CantFindRouterAddress)?;

    if ethernet_packet.get_ethertype() != EtherTypes::Ipv4 {
        return Ok(ScanResult::Filtered);
    }

    let ipv4_packet = Ipv4Packet::new(ethernet_packet.payload()).ok_or(CantFindRouterAddress)?;

    match ipv4_packet.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => {
            let tcp_packet = TcpPacket::new(ipv4_packet.payload()).ok_or(CantFindRouterAddress)?;
            let tcp_flags = tcp_packet.get_flags();
            if tcp_flags == (TcpFlags::SYN | TcpFlags::ACK) {
                return Ok(ScanResult::Open);
            } else if tcp_flags & TCP_FLAGS_RST_MASK == TcpFlags::RST {
                return Ok(ScanResult::Closed);
            } else {
                return Ok(ScanResult::Filtered);
            }
        }
        _ => return Ok(ScanResult::Filtered),
    }
}
