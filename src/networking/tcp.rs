use super::osi_layers::{Layer, NetworkLayer, TransportLayer};
use anyhow::Result;
use log::debug;
use pnet::packet::{
    self,
    ip::IpNextHeaderProtocols,
    ipv4::{self, Ipv4Flags, Ipv4Packet, MutableIpv4Packet},
    tcp::{MutableTcpPacket, TcpFlags},
};
use rand::Rng;
use std::{net::Ipv4Addr, time::Duration};

const IPV4_HEADER_SIZE: usize = 20;
const TCP_HEADER_SIZE: usize = 20;
const TCP_DATA_SIZE: usize = 0;
const TTL: u8 = 64;

pub struct Tcp;

impl Tcp {
    pub fn build_syn_packet(
        src_ip: Ipv4Addr,
        src_port: u16,
        dest_ip: Ipv4Addr,
        dest_port: u16,
    ) -> [u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE] {
        // Generate a random number generator.
        let mut rng = rand::thread_rng();

        // Create IP header.
        let mut packet_buffer = [0u8; IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE];
        let mut ip_header = MutableIpv4Packet::new(&mut packet_buffer).unwrap();
        // IPv4 first header field is always 4.
        ip_header.set_version(4);
        // Minimum header length is 5, which indicates 20 bytes.
        ip_header.set_header_length(5);
        // Sender of the packet.
        ip_header.set_source(src_ip);
        // Receiver of the packet.
        ip_header.set_destination(dest_ip);
        // Defines the entire packet size in bytes. Minimum size is 20 bytes. Maximum size is 65,535 bytes.
        ip_header.set_total_length((IPV4_HEADER_SIZE + TCP_HEADER_SIZE + TCP_DATA_SIZE) as u16);
        // ID field is a unique 16-bit identifier for the packet.
        ip_header.set_identification(rng.gen());
        // Controls fragmentation. DF flag causes packet to be drauped if it cannot be sent without fragmentation.
        ip_header.set_flags(Ipv4Flags::DontFragment);
        // TTL is decremented by one each time the packet is processed by a router.
        // If TTL reaches 0, the packet is discarded and an ICMP time exceeded is sent back to the sender.
        ip_header.set_ttl(TTL);
        // Sets the protocol field to TCP (6).
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        // Checksum used to verify the integrity of the header. Receiver recalculates the checksum and compares it.
        let ip_checksum = ipv4::checksum(&ip_header.to_immutable());
        ip_header.set_checksum(ip_checksum);

        // Create TCP header.
        let mut tcp_header = MutableTcpPacket::new(&mut packet_buffer[IPV4_HEADER_SIZE..]).unwrap();
        // Sending port of the packet.
        tcp_header.set_source(src_port);
        // Receiving port of the packet.
        tcp_header.set_destination(dest_port);
        // The initial sequence number since the SYN flag is set.
        tcp_header.set_sequence(rng.gen());
        // The acknowledgment number.
        tcp_header.set_acknowledgement(rng.gen());
        // Senders should always set this field to 0.
        tcp_header.set_reserved(0);
        // Indicate that this packet is a SYN packet.
        tcp_header.set_flags(TcpFlags::SYN);
        // We set urgent pointer to 0.
        tcp_header.set_urgent_ptr(0);
        // Specifies the number of window size units that we are (sender) willing to receive back.
        tcp_header.set_window(1024);
        // Specifies the size of the TCP header in 32-bit words. Minimum size is 5 words. Maximum size is 15 words.
        tcp_header.set_data_offset(5);
        // Checksum used to verify the integrity of the TCP header.
        let tcp_checksum =
            packet::tcp::ipv4_checksum(&tcp_header.to_immutable(), &src_ip, &dest_ip);
        tcp_header.set_checksum(tcp_checksum);

        packet_buffer
    }

    pub fn send_syn_packet(
        value: u8,
        src_ip: Ipv4Addr,
        src_port: u16,
        dest_ip: Ipv4Addr,
        dest_port: u16,
    ) -> Result<(Option<Vec<u8>>, Option<Duration>)> {
        // Build the TCP SYN packet.
        let packet = Tcp::build_syn_packet(src_ip, src_port, dest_ip, dest_port);

        // Create the match data for layer 3.
        let network_layer = NetworkLayer {
            datalink_layer: None,
            src_addr: Some(dest_ip.into()),
            dest_addr: Some(src_ip.into()),
        };

        // Create the match data for layer 4.
        let transport_layer = TransportLayer {
            network_layer: Some(network_layer),
            src_port: Some(dest_port),
            dest_port: Some(src_port),
        };

        // Matches from layer 4 to layer 2.
        let layer = Layer::Four(transport_layer);

        // Send the packet over the network layer.
        // The packet is handed over to the network layer.
        let (response, rtt) =
            NetworkLayer::send_and_receive(src_ip, dest_ip, &packet, layer, value)?;

        // Parse the IPv4 response.
        match response {
            Some(packet) => {
                match Ipv4Packet::new(&packet) {
                    Some(ip_packet) => {
                        debug!("TCP response: {:?}", ip_packet);
                        // TODO: Parse the TCP response.
                    }
                    None => debug!("No TCP response."),
                }
                Ok((Some(packet), rtt))
            }
            None => Ok((None, None)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use pnet::packet::tcp::TcpPacket;

    #[test]
    fn test_build_syn_packet() {
        let src_ip = Ipv4Addr::new(192, 168, 1, 1);
        let src_port = 12345;
        let dest_ip = Ipv4Addr::new(192, 168, 1, 2);
        let dest_port = 80;

        // Build the SYN packet.
        let packet = Tcp::build_syn_packet(src_ip, src_port, dest_ip, dest_port);

        // Verify the IP header.
        let ip_packet = Ipv4Packet::new(&packet).unwrap();
        assert_eq!(ip_packet.get_version(), 4);
        assert_eq!(ip_packet.get_source(), src_ip);
        assert_eq!(ip_packet.get_destination(), dest_ip);
        assert_eq!(
            ip_packet.get_next_level_protocol(),
            IpNextHeaderProtocols::Tcp
        );

        // Verify the TCP header.
        let tcp_packet = TcpPacket::new(&packet[IPV4_HEADER_SIZE..]).unwrap();
        assert_eq!(tcp_packet.get_source(), src_port);
        assert_eq!(tcp_packet.get_destination(), dest_port);
        assert_eq!(tcp_packet.get_flags(), TcpFlags::SYN);
    }

    #[test]
    fn test_send_syn_packet() -> Result<()> {
        // Local IP address.
        let src_ip = Ipv4Addr::new(192, 168, 178, 26);
        let src_port = 12345;

        // Google's IP address.
        let dest_ip = Ipv4Addr::new(142, 251, 209, 131);
        let dest_port = 80;

        // Send the SYN packet.
        let (packet, rtt) = Tcp::send_syn_packet(1, src_ip, src_port, dest_ip, dest_port)?;

        // Ensure we have received a response packet.
        if let Some(packet) = packet {
            assert!(Ipv4Packet::new(&packet).is_some());
        }

        // Ensure we have received a round-trip time.
        assert!(rtt.is_some());

        Ok(())
    }
}
