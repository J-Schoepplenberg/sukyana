use super::{
    interface::Interface,
    osi_layers::{Layer, NetworkLayer, TransportLayer},
};
use anyhow::Result;
use pnet::packet::{
    icmp::{
        self, destination_unreachable::IcmpCodes, echo_request::MutableEchoRequestPacket,
        IcmpTypes, MutableIcmpPacket,
    },
    ip::IpNextHeaderProtocols,
    ipv4::{self, Ipv4Flags, MutableIpv4Packet},
};
use rand::Rng;
use std::{
    net::Ipv4Addr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const IPV4_HEADER_SIZE: usize = 20;
const ICMP_HEADER_SIZE: usize = 8;
const ICMP_DATA_SIZE: usize = 16;
const TTL: u8 = 64;

pub struct Icmp;

impl Icmp {
    /// Constructs an IP datagram with an ICMP header.
    pub fn build_icmp_packet(
        src_ip: Ipv4Addr,
        dest_ip: Ipv4Addr,
    ) -> [u8; IPV4_HEADER_SIZE + ICMP_HEADER_SIZE + ICMP_DATA_SIZE] {
        let mut rng = rand::thread_rng();
        let mut ip_packet = [0u8; IPV4_HEADER_SIZE + ICMP_HEADER_SIZE + ICMP_DATA_SIZE];

        let mut ip_header = MutableIpv4Packet::new(&mut ip_packet).unwrap();
        ip_header.set_version(4);
        ip_header.set_header_length(5);
        ip_header.set_source(src_ip);
        ip_header.set_destination(dest_ip);
        ip_header.set_total_length((IPV4_HEADER_SIZE + ICMP_HEADER_SIZE + ICMP_DATA_SIZE) as u16);
        ip_header.set_identification(rng.gen());
        ip_header.set_flags(Ipv4Flags::DontFragment);
        ip_header.set_ttl(TTL);
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
        let ip_checksum = ipv4::checksum(&ip_header.to_immutable());
        ip_header.set_checksum(ip_checksum);

        let mut echo_request =
            MutableEchoRequestPacket::new(&mut ip_packet[IPV4_HEADER_SIZE..]).unwrap();
        echo_request.set_icmp_type(IcmpTypes::EchoRequest);
        echo_request.set_icmp_code(IcmpCodes::DestinationNetworkUnreachable);
        echo_request.set_identifier(1);
        echo_request.set_identifier(rng.gen());

        let now = SystemTime::now();
        let duration = now.duration_since(UNIX_EPOCH).unwrap(); // Won't panic
        let secs = duration.as_secs().to_be_bytes();
        let nsecs = duration.subsec_millis().to_be_bytes();
        let mut timestamp = Vec::with_capacity(secs.len() + nsecs.len());
        timestamp.extend_from_slice(&secs);
        timestamp.extend_from_slice(&nsecs);
        echo_request.set_payload(&timestamp);

        let mut icmp_header = MutableIcmpPacket::new(&mut ip_packet[IPV4_HEADER_SIZE..]).unwrap();
        let icmp_checksum = icmp::checksum(&icmp_header.to_immutable());
        icmp_header.set_checksum(icmp_checksum);

        ip_packet
    }

    /// Sends an ICMP packet and parses the response.
    ///
    /// The packet is handed over to the transport layer.
    pub fn send_icmp_packet(
        interface: Interface,
        src_ip: Ipv4Addr,
        dest_ip: Ipv4Addr,
        timeout: Duration,
    ) -> Result<(Option<Vec<u8>>, Duration)> {
        let packet = Icmp::build_icmp_packet(src_ip, dest_ip);

        let network_layer = NetworkLayer {
            datalink_layer: None,
            src_addr: Some(dest_ip.into()),
            dest_addr: Some(src_ip.into()),
        };

        let transport_layer = TransportLayer {
            network_layer: Some(network_layer),
            src_port: None,
            dest_port: None,
        };

        let layer = Layer::Four(transport_layer);

        let (response, rtt) = NetworkLayer::send_and_receive(interface, &packet, layer, timeout)?;

        Ok((response, rtt))
    }
}
