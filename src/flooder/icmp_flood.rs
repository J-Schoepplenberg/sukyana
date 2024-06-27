use crate::{
    errors::ScannerError,
    networking::{icmp::Icmp, interface::Interface, osi_layers::DatalinkLayer},
};
use anyhow::Result;
use pnet::packet::ethernet::EtherTypes;
use std::net::IpAddr;

/// Sends a `number_of_packets` amount of ICMO echo requests to the specified destination.
///
/// Sets the source IP address and port number of each packet to the specified values.
///
/// Does not check if the target can be reached or if it responds.
pub fn icmp_flood(
    interface: Interface,
    src_ip: IpAddr,
    _src_port: u16,
    dest_ip: IpAddr,
    _dest_port: u16,
    number_of_packets: usize,
) -> Result<()> {
    let ipv4_src = match src_ip {
        IpAddr::V4(ip) => ip,
        _ => Err(ScannerError::UnsupportedIpVersion)?,
    };

    let ipv4_dest = match dest_ip {
        IpAddr::V4(ip) => ip,
        _ => Err(ScannerError::UnsupportedIpVersion)?,
    };

    let dest_mac = interface.gateway.mac;

    let iface = interface.convert_interface()?;

    let packet = Icmp::build_icmp_packet(ipv4_src, ipv4_dest);

    DatalinkLayer::send_flood(
        iface,
        &packet,
        number_of_packets,
        dest_mac,
        EtherTypes::Ipv4,
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::networking::interface::Interface;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_icmp_flood() {
        let interface = Interface::new().unwrap();
        let src_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 178, 26));
        let dest_ip = IpAddr::V4(Ipv4Addr::new(142, 251, 209, 131));
        let number_of_packets = 2;

        let result = icmp_flood(interface, src_ip, 0, dest_ip, 0, number_of_packets);

        assert!(result.is_ok());
    }
}
