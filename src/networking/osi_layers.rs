use super::interface::Interface;
use crate::errors::{ChannelError, ScannerError};
use anyhow::Result;
use pnet::{
    datalink::{self, Channel, NetworkInterface},
    packet::{
        arp::ArpPacket,
        ethernet::{EtherType, EtherTypes, EthernetPacket, MutableEthernetPacket},
        ip::IpNextHeaderProtocols,
        ipv4::Ipv4Packet,
        tcp::TcpPacket,
        udp::UdpPacket,
        Packet,
    },
    util::MacAddr,
};
use std::{
    net::IpAddr,
    time::{Duration, Instant},
};

const ETHERNET_HEADER_SIZE: usize = 14;

/// Represents the different layers of the OSI model.
#[allow(dead_code)]
pub enum Layer {
    Two(DatalinkLayer),
    Three(NetworkLayer),
    Four(TransportLayer),
}

/// Represents the datalink layer of the OSI model.
#[derive(Debug, Clone, Copy)]
pub struct DatalinkLayer {
    pub src_mac: Option<MacAddr>,
    pub dest_mac: Option<MacAddr>,
    pub ethernet_type: Option<EtherType>,
}

/// Represents the network layer of the OSI model.
#[derive(Debug, Clone, Copy)]
pub struct NetworkLayer {
    pub datalink_layer: Option<DatalinkLayer>,
    pub src_addr: Option<IpAddr>,
    pub dest_addr: Option<IpAddr>,
}

/// Represents the transport layer of the OSI model.
#[derive(Debug, Clone, Copy)]
pub struct TransportLayer {
    pub network_layer: Option<NetworkLayer>,
    pub src_port: Option<u16>,
    pub dest_port: Option<u16>,
}

impl Layer {
    /// Matches the packet at the given layer.
    pub fn match_layer(&self, packet: &[u8]) -> bool {
        match self {
            Layer::Two(layer) => layer.match_packet(packet),
            Layer::Three(layer) => layer.match_packet(packet),
            Layer::Four(layer) => layer.match_packet(packet),
        }
    }
}

/// Trait for matching packets at different layers of the OSI model.
pub trait MatchLayer {
    /// Matches the packet at the given layer based on src/dest addresses and ports.
    fn match_packet(&self, packet: &[u8]) -> bool;
}

impl MatchLayer for DatalinkLayer {
    /// Matches the packet at the data link layer.
    fn match_packet(&self, packet: &[u8]) -> bool {
        let ethernet_packet = match EthernetPacket::new(packet) {
            Some(p) => p,
            None => return false,
        };

        let match_src = self
            .src_mac
            .map_or(true, |src_mac| src_mac == ethernet_packet.get_source());

        let match_dest = self.dest_mac.map_or(true, |dest_mac| {
            dest_mac == ethernet_packet.get_destination()
        });

        let match_type = self
            .ethernet_type
            .map_or(true, |eth_type| eth_type == ethernet_packet.get_ethertype());

        match_src && match_dest && match_type
    }
}

impl MatchLayer for NetworkLayer {
    /// Matches the packet at the network layer.
    ///
    /// Must also match at the data link layer.
    fn match_packet(&self, packet: &[u8]) -> bool {
        let ethernet_packet = match EthernetPacket::new(packet) {
            Some(p) => p,
            None => return false,
        };

        if !self
            .datalink_layer
            .as_ref()
            .map_or(true, |layer| layer.match_packet(packet))
        {
            return false;
        }

        match ethernet_packet.get_ethertype() {
            EtherTypes::Ipv4 => {
                let ipv4_packet = match Ipv4Packet::new(ethernet_packet.payload()) {
                    Some(packet) => packet,
                    None => return false,
                };

                let match_src = self.src_addr.map_or(true, |src| match src {
                    IpAddr::V4(src_ip) => ipv4_packet.get_source() == src_ip,
                    _ => false,
                });

                let match_dest = self.dest_addr.map_or(true, |dest| match dest {
                    IpAddr::V4(dest_ip) => ipv4_packet.get_destination() == dest_ip,
                    _ => false,
                });

                match_src && match_dest
            }
            EtherTypes::Arp => {
                let arp_packet = match ArpPacket::new(ethernet_packet.payload()) {
                    Some(packet) => packet,
                    None => return false,
                };

                let match_src = self.src_addr.map_or(true, |src| match src {
                    IpAddr::V4(src_ip) => arp_packet.get_sender_proto_addr() == src_ip,
                    _ => false,
                });

                let match_dest = self.dest_addr.map_or(true, |dest| match dest {
                    IpAddr::V4(dest_ip) => arp_packet.get_target_proto_addr() == dest_ip,
                    _ => false,
                });

                match_src && match_dest
            }
            _ => false, // IPv6, etc.
        }
    }
}

impl MatchLayer for TransportLayer {
    /// Matches the packet at the transport layer.
    ///
    /// Must also match at the network layer and data link layer.
    fn match_packet(&self, packet: &[u8]) -> bool {
        let ethernet_packet = match EthernetPacket::new(packet) {
            Some(p) => p,
            None => return false,
        };

        if !self
            .network_layer
            .as_ref()
            .map_or(true, |layer| layer.match_packet(packet))
        {
            return false;
        }

        let ports = match ethernet_packet.get_ethertype() {
            EtherTypes::Ipv4 => {
                let ipv4_packet = match Ipv4Packet::new(ethernet_packet.payload()) {
                    Some(packet) => packet,
                    None => return false,
                };

                match ipv4_packet.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => TcpPacket::new(ipv4_packet.payload())
                        .map(|tcp| (tcp.get_source(), tcp.get_destination())),
                    IpNextHeaderProtocols::Udp => UdpPacket::new(ipv4_packet.payload())
                        .map(|udp| (udp.get_source(), udp.get_destination())),
                    IpNextHeaderProtocols::Icmp => return true,
                    _ => None,
                }
            }
            _ => None,
        };

        let (src_port, dest_port) = match ports {
            Some(ports) => ports,
            None => return false,
        };

        let match_src_port = self.src_port.map_or(true, |port| port == src_port);

        let match_dest_port = self.dest_port.map_or(true, |port| port == dest_port);

        match_src_port && match_dest_port
    }
}

impl DatalinkLayer {
    /// Mutates an Ethernet packet in-place.
    pub fn build_ethernet_packet(
        src_mac: MacAddr,
        dest_mac: MacAddr,
        ethertype: EtherType,
        payload: &[u8],
        packet: &mut [u8],
    ) {
        let mut ethernet_packet = MutableEthernetPacket::new(packet).unwrap();

        ethernet_packet.set_source(src_mac);
        ethernet_packet.set_destination(dest_mac);
        ethernet_packet.set_ethertype(ethertype);
        ethernet_packet.set_payload(payload);
    }

    /// Sends a packet over a data link channel and waits `timeout` for a response.
    ///
    /// Processes the ethernet frames in the channel and matches them against the provided layer data.
    ///
    /// Returns a matching response and the round-trip time.
    pub fn send_and_receive(
        interface: &NetworkInterface,
        dest_mac: MacAddr,
        ethertype: EtherType,
        payload: &[u8],
        layers: Layer,
        timeout: Duration,
    ) -> Result<(Option<Vec<u8>>, Duration)> {
        let (mut sender, mut receiver) = match datalink::channel(interface, Default::default())? {
            Channel::Ethernet(tx, rx) => (tx, rx),
            _ => return Err(ChannelError::UnexpectedChannelType.into()),
        };

        let src_mac = interface.mac.ok_or(ScannerError::CantFindInterfaceMac)?;

        let mut build_packet_fn = |packet: &mut [u8]| {
            Self::build_ethernet_packet(src_mac, dest_mac, ethertype, payload, packet);
        };

        let send_time = Instant::now();

        sender
            .build_and_send(
                1,
                ETHERNET_HEADER_SIZE + payload.len(),
                &mut build_packet_fn,
            )
            .ok_or(ChannelError::SendError)??;

        let deadline = send_time + timeout;

        while Instant::now() < deadline {
            if let Ok(response) = receiver.next() {
                if layers.match_layer(response) {
                    return Ok((Some(response.to_vec()), send_time.elapsed()));
                }
            }
        }

        Ok((None, send_time.elapsed()))
    }

    /// Sends a packet over a data link channel.
    ///
    /// Does not wait or listen for a response.
    pub fn send_flood(
        interface: NetworkInterface,
        payload: &[u8],
        number_of_packets: usize,
        dest_mac: MacAddr,
        ethertype: EtherType,
    ) -> Result<()> {
        let (mut sender, mut _receiver) = match datalink::channel(&interface, Default::default())? {
            Channel::Ethernet(tx, rx) => (tx, rx),
            _ => return Err(ChannelError::UnexpectedChannelType.into()),
        };

        let src_mac = interface.mac.ok_or(ScannerError::CantFindInterfaceMac)?;

        let mut build_packet_fn = |packet: &mut [u8]| {
            Self::build_ethernet_packet(src_mac, dest_mac, ethertype, payload, packet);
        };

        sender
            .build_and_send(
                number_of_packets,
                ETHERNET_HEADER_SIZE + payload.len(),
                &mut build_packet_fn,
            )
            .ok_or(ChannelError::SendError)??;

        Ok(())
    }
}

impl NetworkLayer {
    /// Hands over the packet to the data link layer.
    ///
    /// Converts the interface to a `pnet::datalink::NetworkInterface`.
    ///
    /// Returns the response and the round-trip time.
    pub fn send_and_receive(
        interface: Interface,
        packet: &[u8],
        layers: Layer,
        timeout: Duration,
    ) -> Result<(Option<Vec<u8>>, Duration)> {
        let dest_mac = interface.gateway.mac;

        let iface = interface.convert_interface()?;

        let (response, rtt) = DatalinkLayer::send_and_receive(
            &iface,
            dest_mac,
            EtherTypes::Ipv4,
            packet,
            layers,
            timeout,
        )?;

        Ok((response, rtt))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::networking::tcp::Tcp;
    use pnet::packet::tcp::TcpFlags;
    use std::net::Ipv4Addr;

    /// Creates an Ethernet packet.
    fn build_ethernet_packet(
        src_mac: MacAddr,
        dest_mac: MacAddr,
        ethertype: EtherType,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut ethernet_buffer = [0u8; 4096];
        let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

        ethernet_packet.set_source(src_mac);
        ethernet_packet.set_destination(dest_mac);
        ethernet_packet.set_ethertype(ethertype);
        ethernet_packet.set_payload(payload);

        ethernet_buffer[..(ETHERNET_HEADER_SIZE + payload.len())].to_vec()
    }

    #[test]
    fn test_layers_match() {
        // Set up the data we need for the layers.
        let src_mac = MacAddr::new(0, 1, 2, 3, 4, 5);
        let dest_mac = MacAddr::new(6, 7, 8, 9, 10, 11);
        let ethertype = EtherTypes::Ipv4;
        let src_ip = Ipv4Addr::new(192, 168, 0, 1);
        let dest_ip = Ipv4Addr::new(192, 168, 0, 2);
        let src_port = 12345;
        let dest_port = 80;

        // Create the data link layer.
        let datalink_layer = DatalinkLayer {
            src_mac: Some(src_mac),
            dest_mac: Some(dest_mac),
            ethernet_type: Some(ethertype),
        };

        // Create the network layer.
        let network_layer = NetworkLayer {
            datalink_layer: Some(datalink_layer),
            src_addr: Some(IpAddr::V4(src_ip)),
            dest_addr: Some(IpAddr::V4(dest_ip)),
        };

        // Create the transport layer.
        let transport_layer = TransportLayer {
            network_layer: Some(network_layer),
            src_port: Some(src_port),
            dest_port: Some(dest_port),
        };

        // The packet should match all layers.
        let tcp_packet_1 =
            Tcp::build_tcp_packet(src_ip, src_port, dest_ip, dest_port, TcpFlags::SYN);
        let ethernet_packet_1 = build_ethernet_packet(src_mac, dest_mac, ethertype, &tcp_packet_1);
        assert!(transport_layer.match_packet(&ethernet_packet_1));

        // The packet should not match anymore since src_ip and dest_port are different.
        let tcp_packet_2 = Tcp::build_tcp_packet(
            Ipv4Addr::new(10, 0, 0, 1),
            src_port,
            dest_ip,
            443,
            TcpFlags::SYN,
        );
        let ethernet_packet_2 = build_ethernet_packet(src_mac, dest_mac, ethertype, &tcp_packet_2);
        assert!(!transport_layer.match_packet(&ethernet_packet_2));
    }
}
