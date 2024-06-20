use super::osi_layers::{Layer, NetworkLayer, TransportLayer};
use anyhow::Result;
use pnet::packet::{
    ip::IpNextHeaderProtocols,
    ipv4::{self, Ipv4Flags, MutableIpv4Packet},
    udp::{ipv4_checksum, MutableUdpPacket},
};
use rand::Rng;
use std::{net::Ipv4Addr, time::Duration};

const IPV4_HEADER_SIZE: usize = 20;
const UDP_HEADER_SIZE: usize = 8;
const UDP_DATA_SIZE: usize = 20;
const TTL: u8 = 64;

pub struct Udp;

impl Udp {
    /// Constructs an IP datagram with a UDP header.
    pub fn build_udp_packet(
        src_ip: Ipv4Addr,
        src_port: u16,
        dest_ip: Ipv4Addr,
        dest_port: u16,
    ) -> [u8; IPV4_HEADER_SIZE + UDP_HEADER_SIZE + UDP_DATA_SIZE] {
        let mut rng = rand::thread_rng();
        let mut ip_packet = [0u8; IPV4_HEADER_SIZE + UDP_HEADER_SIZE + UDP_DATA_SIZE];

        let mut ip_header = MutableIpv4Packet::new(&mut ip_packet).unwrap();
        ip_header.set_version(4);
        ip_header.set_header_length(5);
        ip_header.set_source(src_ip);
        ip_header.set_destination(dest_ip);
        ip_header.set_total_length((IPV4_HEADER_SIZE + UDP_HEADER_SIZE + UDP_DATA_SIZE) as u16);
        ip_header.set_identification(rng.gen());
        ip_header.set_flags(Ipv4Flags::DontFragment);
        ip_header.set_ttl(TTL);
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        let ip_checksum = ipv4::checksum(&ip_header.to_immutable());
        ip_header.set_checksum(ip_checksum);

        let mut udp_header = MutableUdpPacket::new(&mut ip_packet[IPV4_HEADER_SIZE..]).unwrap();
        udp_header.set_source(src_port);
        udp_header.set_destination(dest_port);
        udp_header.set_length((UDP_HEADER_SIZE + UDP_DATA_SIZE) as u16);
        udp_header.set_payload(&vec![0x41; UDP_DATA_SIZE]);
        let udp_checksum = ipv4_checksum(&udp_header.to_immutable(), &src_ip, &dest_ip);
        udp_header.set_checksum(udp_checksum);

        ip_packet
    }

    pub fn send_udp_packet(
        src_ip: Ipv4Addr,
        src_port: u16,
        dest_ip: Ipv4Addr,
        dest_port: u16,
        timeout: Duration,
    ) -> Result<(Option<Vec<u8>>, Duration)> {
        let packet = Udp::build_udp_packet(src_ip, src_port, dest_ip, dest_port);

        let network_layer = NetworkLayer {
            datalink_layer: None,
            src_addr: Some(dest_ip.into()),
            dest_addr: Some(src_ip.into()),
        };

        let transport_layer = TransportLayer {
            network_layer: Some(network_layer),
            src_port: Some(dest_port),
            dest_port: Some(src_port),
        };

        let layers = Layer::Four(transport_layer);

        let (response, rtt) =
            NetworkLayer::send_and_receive(src_ip, dest_ip, &packet, layers, timeout)?;

        Ok((response, rtt))
    }
}
