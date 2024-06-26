use super::engine::ScanResult;
use crate::{
    errors::ScannerError,
    networking::{interface::Interface, tcp::Tcp},
};
use anyhow::Result;
use pnet::packet::{
    ethernet::EthernetPacket,
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    tcp::{TcpFlags, TcpPacket},
    Packet,
};
use std::{
    net::{IpAddr, SocketAddr, TcpStream},
    time::{Duration, Instant},
};

/// TCP SYN determines the status of ports on a target machine.
///
/// Scan sends TCP packets with the SYN flag set.
///
/// It does not complete the three-way handshake and does not need to tear down connections.
/// The most common scan type due to its speed and stealthiness. This method usually allows
/// to scan through stateful firewalls, since they typically allow SYN packets for new connections.
///
/// RFC 793 expected behavior is that an open port will respond with a SYN-ACK flag.
/// A closed port will respond with a RST flag. No response indicates a filtered port.
/// Filtered ports may also respond with an ICMP Type 3 unreachable error, but we can ignore this.
pub fn tcp_syn_scan(
    interface: Interface,
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

    let (response, rtt) = Tcp::send_tcp_packet(
        interface,
        ipv4_src,
        src_port,
        ipv4_dest,
        dest_port,
        TcpFlags::SYN,
        timeout,
    )?;

    // No response -> filtered.
    let packet = match response {
        Some(packet) => packet,
        None => return Ok((ScanResult::Filtered, rtt)),
    };

    let ethernet_packet =
        EthernetPacket::new(&packet).ok_or(ScannerError::CantCreateEthernetPacket)?;

    let ipv4_packet =
        Ipv4Packet::new(ethernet_packet.payload()).ok_or(ScannerError::CantCreateIpv4Packet)?;

    // Not a TCP packet, perhaps ICMP unreachable error -> filtered.
    if ipv4_packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        return Ok((ScanResult::Filtered, rtt));
    }

    let tcp_packet =
        TcpPacket::new(ipv4_packet.payload()).ok_or(ScannerError::CantCreateTcpPacket)?;

    let tcp_flags = tcp_packet.get_flags();

    // SYN/ACK flag set -> open.
    if tcp_flags & TcpFlags::SYN != 0 && tcp_flags & TcpFlags::ACK != 0 {
        return Ok((ScanResult::Open, rtt));
    }

    // RST flag set -> closed.
    if tcp_flags & TcpFlags::RST != 0 {
        return Ok((ScanResult::Closed, rtt));
    }

    Err(ScannerError::UnexpectedTcpFlags.into())
}

/// TCP connect determines if a port is open on a target machine.
///
/// Establishes a full TCP connection, completing the three-way handshake.
/// If the handshake cannot be established, the port is considered as closed.
/// It can't distinguish filtered ports.
///
/// Involves sending a signifcant number of packets and is therefore slower than a SYN scan.
/// It also causes considerable noise in event logs and is easily detected.
pub fn tcp_connect_scan(
    _interface: Interface,
    _src_ip: IpAddr,
    _src_port: u16,
    dest_ip: IpAddr,
    dest_port: u16,
    timeout: Duration,
) -> Result<(ScanResult, Duration)> {
    let socket = SocketAddr::new(dest_ip, dest_port);
    let start_time = Instant::now();
    match TcpStream::connect_timeout(&socket, timeout) {
        Ok(_) => Ok((ScanResult::Open, start_time.elapsed())),
        Err(_) => Ok((ScanResult::Closed, start_time.elapsed())),
    }
}

/// TCP ACK gathers information about the firewall or ACL configuration on a target machine.
///
/// The goal is to discover details about filter configurations rather than port state.
/// In practice often combined with TCP SYN scanning to obtain a complete picture of the target.
///
/// Scan sends TCP packets with the ACK flag set.
///
/// RFC 793 expected behavior is that unfiltered open and closed ports will respond with a RST flag.
/// If no response is received, the port is likely filtered.
pub fn tcp_ack_scan(
    interface: Interface,
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

    let (response, rtt) = Tcp::send_tcp_packet(
        interface,
        ipv4_src,
        src_port,
        ipv4_dest,
        dest_port,
        TcpFlags::ACK,
        timeout,
    )?;

    // No response -> filtered.
    let packet = match response {
        Some(packet) => packet,
        None => return Ok((ScanResult::Filtered, rtt)),
    };

    let ethernet_packet =
        EthernetPacket::new(&packet).ok_or(ScannerError::CantCreateEthernetPacket)?;

    let ipv4_packet =
        Ipv4Packet::new(ethernet_packet.payload()).ok_or(ScannerError::CantCreateIpv4Packet)?;

    // Not a TCP packet, perhaps ICMP unreachable error -> filtered.
    if ipv4_packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        return Ok((ScanResult::Filtered, rtt));
    }

    let tcp_packet =
        TcpPacket::new(ipv4_packet.payload()).ok_or(ScannerError::CantCreateTcpPacket)?;

    let tcp_flags = tcp_packet.get_flags();

    // RST flag set -> closed.
    if tcp_flags & TcpFlags::RST != 0 {
        return Ok((ScanResult::Unfiltered, rtt));
    }

    Err(ScannerError::UnexpectedTcpFlags.into())
}

/// TCP FIN determines if a port is closed on a target machine.
///
/// Scan sends TCP packets with the FIN flag set. Considered to be relatively stealthy.
///
/// RFC 793 expected behavior is that a closed port will respond with a RST flag.
/// An open port will ignore the packet.
pub fn tcp_fin_scan(
    interface: Interface,
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

    let (response, rtt) = Tcp::send_tcp_packet(
        interface,
        ipv4_src,
        src_port,
        ipv4_dest,
        dest_port,
        TcpFlags::FIN,
        timeout,
    )?;

    // No response -> open or filtered.
    let packet = match response {
        Some(packet) => packet,
        None => return Ok((ScanResult::OpenOrFiltered, rtt)),
    };

    let ethernet_packet =
        EthernetPacket::new(&packet).ok_or(ScannerError::CantCreateEthernetPacket)?;

    let ipv4_packet =
        Ipv4Packet::new(ethernet_packet.payload()).ok_or(ScannerError::CantCreateIpv4Packet)?;

    // Not a TCP packet, perhaps ICMP unreachable error -> filtered.
    if ipv4_packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        return Ok((ScanResult::Filtered, rtt));
    }

    let tcp_packet =
        TcpPacket::new(ipv4_packet.payload()).ok_or(ScannerError::CantCreateTcpPacket)?;

    let tcp_flags = tcp_packet.get_flags();

    // RST flag set -> closed.
    if tcp_flags & TcpFlags::RST != 0 {
        return Ok((ScanResult::Closed, rtt));
    }

    Err(ScannerError::UnexpectedTcpFlags.into())
}

/// TCP XMAS determines if a port is closed on a target machine.
///
/// Scan sends TCP packets with FIN, PSH and URG flags set. They are considered illegal based on RFC 793.
/// Firewalls are often configured to block SYN packets, but not out-of-state packets.
/// Since this scan is obviously rule-breaking, it is typically flagged by any decent IDS.
///
/// RFC 793 expected behavior is that a closed port will respond with a RST flag.
/// An open port ignores packets with out-of-state flags.
pub fn tcp_xmas_scan(
    interface: Interface,
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

    let (response, rtt) = Tcp::send_tcp_packet(
        interface,
        ipv4_src,
        src_port,
        ipv4_dest,
        dest_port,
        TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG,
        timeout,
    )?;

    // No response -> open or filtered.
    let packet = match response {
        Some(packet) => packet,
        None => return Ok((ScanResult::OpenOrFiltered, rtt)),
    };

    let ethernet_packet =
        EthernetPacket::new(&packet).ok_or(ScannerError::CantCreateEthernetPacket)?;

    let ipv4_packet =
        Ipv4Packet::new(ethernet_packet.payload()).ok_or(ScannerError::CantCreateIpv4Packet)?;

    // Not a TCP packet, perhaps ICMP unreachable error -> filtered.
    if ipv4_packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        return Ok((ScanResult::Filtered, rtt));
    }

    let tcp_packet =
        TcpPacket::new(ipv4_packet.payload()).ok_or(ScannerError::CantCreateTcpPacket)?;

    let tcp_flags = tcp_packet.get_flags();

    // RST flag set -> closed.
    if tcp_flags & TcpFlags::RST != 0 {
        return Ok((ScanResult::Closed, rtt));
    }

    Err(ScannerError::UnexpectedTcpFlags.into())
}

/// TCP NULL determines if a port is closed on a target machine.
///
/// Scan sends TCP packets with no flags set. They are considered illegal based on RFC 793.
/// Similarly to the XMAS scan, this scan is rule-breaking and typically flagged by any decent IDS.
///
/// RFC 793 expected behavior is that a closed port will respond with a RST flag.
/// An open port will ignore the packet.
pub fn tcp_null_scan(
    interface: Interface,
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

    let (response, rtt) = Tcp::send_tcp_packet(
        interface, ipv4_src, src_port, ipv4_dest, dest_port, 0, timeout,
    )?;

    // No response -> open or filtered.
    let packet = match response {
        Some(packet) => packet,
        None => return Ok((ScanResult::OpenOrFiltered, rtt)),
    };

    let ethernet_packet =
        EthernetPacket::new(&packet).ok_or(ScannerError::CantCreateEthernetPacket)?;

    let ipv4_packet =
        Ipv4Packet::new(ethernet_packet.payload()).ok_or(ScannerError::CantCreateIpv4Packet)?;

    // Not a TCP packet, perhaps ICMP unreachable error -> filtered.
    if ipv4_packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        return Ok((ScanResult::Filtered, rtt));
    }

    let tcp_packet =
        TcpPacket::new(ipv4_packet.payload()).ok_or(ScannerError::CantCreateTcpPacket)?;

    let tcp_flags = tcp_packet.get_flags();

    // RST flag set -> closed.
    if tcp_flags & TcpFlags::RST != 0 {
        return Ok((ScanResult::Closed, rtt));
    }

    Err(ScannerError::UnexpectedTcpFlags.into())
}

/// TCP Window works exactly the same as ACK scans, but examines the window field in the TCP header of RST packets.
///
/// Open ports use a positive window size, while closed ports use a zero window size.
///
/// Thus, it does not list ports as unfiltered, but determines if a port is open or closed.
pub fn tcp_window_scan(
    interface: Interface,
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

    let (response, rtt) = Tcp::send_tcp_packet(
        interface,
        ipv4_src,
        src_port,
        ipv4_dest,
        dest_port,
        TcpFlags::ACK,
        timeout,
    )?;

    // No response -> filtered.
    let packet = match response {
        Some(packet) => packet,
        None => return Ok((ScanResult::Filtered, rtt)),
    };

    let ethernet_packet =
        EthernetPacket::new(&packet).ok_or(ScannerError::CantCreateEthernetPacket)?;

    let ipv4_packet =
        Ipv4Packet::new(ethernet_packet.payload()).ok_or(ScannerError::CantCreateIpv4Packet)?;

    // Not a TCP packet, perhaps ICMP unreachable error -> filtered.
    if ipv4_packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        return Ok((ScanResult::Filtered, rtt));
    }

    let tcp_packet =
        TcpPacket::new(ipv4_packet.payload()).ok_or(ScannerError::CantCreateTcpPacket)?;

    let tcp_flags = tcp_packet.get_flags();

    // RST flag set.
    // Non-zero window size -> open.
    // Zero window size -> closed.
    if tcp_flags & TcpFlags::RST != 0 {
        if tcp_packet.get_window() > 0 {
            return Ok((ScanResult::Open, rtt));
        } else {
            return Ok((ScanResult::Closed, rtt));
        }
    }

    Err(ScannerError::UnexpectedTcpFlags.into())
}

/// TCP Maimon determines if a port is closed on a target machine.
///
/// Works exactly the same as NULL, FIN and XMAS scans, but with the FIN and ACK flags set.
///
/// Expected behavior is that a closed port will respond with a RST flag.
/// An open port should also respond with a RST flag, but many systems ignore this packet.
pub fn tcp_maimon_scan(
    interface: Interface,
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

    let (response, rtt) = Tcp::send_tcp_packet(
        interface,
        ipv4_src,
        src_port,
        ipv4_dest,
        dest_port,
        TcpFlags::FIN | TcpFlags::ACK,
        timeout,
    )?;

    // No response -> open or filtered.
    let packet = match response {
        Some(packet) => packet,
        None => return Ok((ScanResult::OpenOrFiltered, rtt)),
    };

    let ethernet_packet =
        EthernetPacket::new(&packet).ok_or(ScannerError::CantCreateEthernetPacket)?;

    let ipv4_packet =
        Ipv4Packet::new(ethernet_packet.payload()).ok_or(ScannerError::CantCreateIpv4Packet)?;

    // Not a TCP packet, perhaps ICMP unreachable error -> filtered.
    if ipv4_packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        return Ok((ScanResult::Filtered, rtt));
    }

    let tcp_packet =
        TcpPacket::new(ipv4_packet.payload()).ok_or(ScannerError::CantCreateTcpPacket)?;

    let tcp_flags = tcp_packet.get_flags();

    // RST flag set -> closed.
    if tcp_flags & TcpFlags::RST != 0 {
        return Ok((ScanResult::Closed, rtt));
    }

    Err(ScannerError::UnexpectedTcpFlags.into())
}
