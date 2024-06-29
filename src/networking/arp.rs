use super::{
    interface::Interface,
    osi_layers::{DatalinkLayer, Layer, NetworkLayer},
};
use anyhow::Result;
use pnet::{
    packet::{
        arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket},
        ethernet::{EtherTypes, EthernetPacket},
        Packet,
    },
    util::MacAddr,
};
use std::{net::Ipv4Addr, time::Duration};

pub struct Arp;

impl Arp {
    /// Constructs an ARP packet.
    pub fn build_arp_packet(src_mac: MacAddr, src_ip: Ipv4Addr, dest_ip: Ipv4Addr) -> [u8; 28] {
        let mut arp_packet = [0u8; 28];
        let mut arp_header = MutableArpPacket::new(&mut arp_packet).unwrap();

        arp_header.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_header.set_protocol_type(EtherTypes::Ipv4);
        arp_header.set_hw_addr_len(6);
        arp_header.set_proto_addr_len(4);
        arp_header.set_operation(ArpOperations::Request);
        arp_header.set_sender_hw_addr(src_mac);
        arp_header.set_sender_proto_addr(src_ip);
        arp_header.set_target_hw_addr(MacAddr::zero());
        arp_header.set_target_proto_addr(dest_ip);

        arp_packet
    }

    /// Sends an ARP request to retrieve a MAC address.
    ///
    /// The ARP packet is handed over to the data link layer.
    pub fn send_request(
        interface: Interface,
        src_ip: Ipv4Addr,
        dest_ip: Ipv4Addr,
        timeout: Duration,
    ) -> Result<(Option<MacAddr>, Duration)> {
        let src_mac = interface.mac;

        let iface = interface.convert_interface()?;

        let arp_packet = Arp::build_arp_packet(src_mac, src_ip, dest_ip);

        let ethernet_type = EtherTypes::Arp;

        let data_link_layer = DatalinkLayer {
            src_mac: None,
            dest_mac: None,
            ethernet_type: Some(ethernet_type),
        };

        let network_layer = NetworkLayer {
            datalink_layer: Some(data_link_layer),
            src_addr: Some(dest_ip.into()),
            dest_addr: Some(src_ip.into()),
        };

        let layer = Layer::Three(network_layer);

        let (response, rtt) = DatalinkLayer::send_and_receive(
            &iface,
            MacAddr::broadcast(),
            ethernet_type,
            &arp_packet,
            layer,
            timeout,
        )?;

        match response {
            Some(packet) => Ok((Arp::get_mac_address(&packet), rtt)),
            None => Ok((None, rtt)),
        }
    }

    /// Extracts the MAC address from an ARP packet.
    pub fn get_mac_address(packet: &[u8]) -> Option<MacAddr> {
        let response = EthernetPacket::new(packet)?;
        if response.get_ethertype() == EtherTypes::Arp {
            let arp_packet = ArpPacket::new(response.payload())?;
            Some(arp_packet.get_sender_hw_addr())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_send_request_and_get_mac() -> Result<()> {
        // Get the default interface.
        let iface = Interface::new()?;

        // Local IP address.
        let src_ip = Ipv4Addr::new(192, 168, 178, 26);

        // Local IP address.
        let router_ip = Ipv4Addr::new(192, 168, 178, 26);

        // Time to wait for a response.
        let timeout = Duration::from_secs(5);

        // Send an ARP request to the router. Parses the MAC address from the response.
        let (response, _rtt) = Arp::send_request(iface, src_ip, router_ip, timeout).unwrap();

        // Ensure we received a response.
        assert!(response.is_some());

        Ok(())
    }
}
