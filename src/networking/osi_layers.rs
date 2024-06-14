use anyhow::Result;
use pnet::{
    datalink::{self, DataLinkReceiver, DataLinkSender, NetworkInterface}, packet::{
        ethernet::{EtherType, EtherTypes, EthernetPacket, MutableEthernetPacket},
        ip::IpNextHeaderProtocols,
        ipv4::Ipv4Packet,
        tcp::TcpPacket,
        Packet,
    }, util::MacAddr
};
use std::{net::{IpAddr, Ipv4Addr}, process::Command, time::{Duration, Instant}};

use crate::{errors::{CantFindInterface, CantFindMacAddress, CantFindRouterAddress, CreateDatalinkChannelFailed}, networking::arp::Arp};

use super::interface::Interface;

/// Represents the different layers of the OSI model.
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
    /// Matches the packet at the datalink layer.
    ///
    /// Checks for the source and destination MAC addresses and the Ethernet type.
    fn match_packet(&self, packet: &[u8]) -> bool {
        // Create an Ethernet packet from the payload.
        let ethernet_packet = match EthernetPacket::new(packet) {
            Some(p) => p,
            None => return false,
        };

        // Check if the source MAC address matches
        let match_1 = match self.src_mac {
            Some(src_mac) => src_mac == ethernet_packet.get_source(),
            None => true,
        };

        // Check if the destination MAC address matches
        let match_2 = match self.dest_mac {
            Some(dest_mac) => dest_mac == ethernet_packet.get_destination(),
            None => true,
        };

        let match_3 = match self.ethernet_type {
            Some(ethernet_type) => ethernet_type == ethernet_packet.get_ethertype(),
            None => true,
        };

        match_1 && match_2 && match_3
    }
}

impl MatchLayer for NetworkLayer {
    /// Matches the packet at the network layer.
    ///
    /// First matches at the data link layer, then checks the source and destination IP addresses.
    ///
    /// Only matches IPv4 packets.
    fn match_packet(&self, packet: &[u8]) -> bool {
        // Create an Ethernet packet from the payload.
        let ethernet_packet = match EthernetPacket::new(packet) {
            Some(p) => p,
            None => return false,
        };

        // Check if layer 2 (datalink) matches.
        let match_1 = match self.datalink_layer {
            Some(layer) => layer.match_packet(packet),
            None => true,
        };

        // Check if layer 3 (network) matches.
        match ethernet_packet.get_ethertype() {
            // Create an IPv4 packet from the payload.
            EtherTypes::Ipv4 => {
                let ipv4_packet = match Ipv4Packet::new(ethernet_packet.payload()) {
                    Some(packet) => packet,
                    None => return false,
                };

                // Check if the source IP address matches
                let match_2 = match self.src_addr {
                    Some(src_addr) => match src_addr {
                        IpAddr::V4(src_ip) => ipv4_packet.get_source() == src_ip,
                        _ => false,
                    },
                    None => true,
                };

                // Check if the destination IP address matches
                let match_3 = match self.dest_addr {
                    Some(dest_addr) => match dest_addr {
                        IpAddr::V4(dest_ip) => ipv4_packet.get_destination() == dest_ip,
                        _ => false,
                    },
                    None => true,
                };

                match_1 && match_2 && match_3
            }
            _ => false, // IPv6, ARP, etc.
            // TODO: Match ARP packets.
        }
    }
}

impl MatchLayer for TransportLayer {
    /// Matches the packet at the transport layer.
    ///
    /// First matches at the network layer, which also matches on the data link layer.
    ///
    /// Then checks the source and destination ports.
    ///
    /// Only matches TCP packets.
    fn match_packet(&self, packet: &[u8]) -> bool {
        // Create an Ethernet packet from the payload.
        let ethernet_packet = match EthernetPacket::new(packet) {
            Some(p) => p,
            None => return false,
        };

        // Check if layer 3 (network) matches.
        let match_1 = match self.network_layer {
            Some(layer) => layer.match_packet(packet),
            None => true,
        };

        let (response_src_port, response_dest_port) = match ethernet_packet.get_ethertype() {
            EtherTypes::Ipv4 => {
                // Create an IPv4 packet from the payload.
                let ipv4_packet = match Ipv4Packet::new(ethernet_packet.payload()) {
                    Some(packet) => packet,
                    None => return false,
                };

                // Extract the source and destination ports from the TCP packet.
                match ipv4_packet.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        let tcp_packet = match TcpPacket::new(ipv4_packet.payload()) {
                            Some(packet) => packet,
                            None => return false,
                        };
                        (tcp_packet.get_source(), tcp_packet.get_destination())
                    }
                    _ => (0, 0),
                }
            }
            _ => (0, 0), // IPv6 etc.
        };

        // Check if the source port matches.
        let match_2 = match self.src_port {
            Some(src_port) => src_port == response_src_port,
            None => true,
        };

        // Check if the destination port matches.
        let match_3 = match self.dest_port {
            Some(dest_port) => dest_port == response_dest_port,
            None => true,
        };

        match_1 && match_2 && match_3
    }
}

const ETHERNET_BUFFER_SIZE: usize = 4096;
const ETHERNET_HEADER_SIZE: usize = 14;


impl DatalinkLayer {
    /// Creates a data link layer channel for sending and receiving packets.
    pub fn create_channel(
        interface: &NetworkInterface,
    ) -> Result<Option<(Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>)>> {
        match datalink::channel(interface, Default::default()) {
            Ok(pnet::datalink::Channel::Ethernet(tx, rx)) => Ok(Some((tx, rx))),
            Ok(_) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn send_and_receive(
        interface: NetworkInterface,
        dest_mac: MacAddr,
        ethernet_type: EtherType,
        payload_buffer: &[u8],
        layers: Layer,
        val: u8,
    ) -> Result<(Option<Vec<u8>>, Option<Duration>)> {
        // Create datalink channel.
        let (mut sender, mut receiver) = match DatalinkLayer::create_channel(&interface)? {
            Some((s, r)) => (s, r),
            None => return Err(CreateDatalinkChannelFailed.into()),
        };

        // Determine the source MAC address.
        let src_mac = if dest_mac == MacAddr::zero() {
            MacAddr::zero()
        } else {
            match interface.mac {
                Some(mac) => mac,
                None => return Err(CantFindMacAddress.into()),
            }
        };

        // Create Ethernet packet.
        let mut ethernet_buffer = [0u8; ETHERNET_BUFFER_SIZE];
        let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
        ethernet_packet.set_destination(dest_mac);
        ethernet_packet.set_source(src_mac);
        ethernet_packet.set_ethertype(ethernet_type);
        ethernet_packet.set_payload(payload_buffer);

        // Start the timer.
        let send_time = Instant::now();

        // Construct the final payload.
        let final_packet =
            ethernet_buffer[..(ETHERNET_HEADER_SIZE + payload_buffer.len())].to_vec();

        // Send the packet.
        match sender.send_to(&final_packet, Some(interface)) {
            Some(r) => match r {
                Err(e) => return Err(e.into()),
                _ => (),
            },
            None => (),
        }

        println!("Sent {val}.");

        // Receive the response. Timeout after 5 seconds.
        let mut response_buffer: Vec<u8>;
        loop {
            match receiver.next() {
                Ok(response_packet) => {
                    response_buffer = response_packet.to_vec();
                    match layers.match_layer(&response_buffer) {
                        true => {
                            println!("Matched.");
                            break;
                        }
                        false => (),
                    }
                    if send_time.elapsed() > Duration::from_secs(5) {
                        println!("Timeout.");
                        break;
                    }
                }
                Err(e) => {
                    panic!("An error occurred while reading: {}", e);
                }
            }
        }

        // Calculate the round-trip time.
        let rtt = send_time.elapsed();

        // Return the response and the round-trip time.
        Ok((Some(response_buffer), Some(rtt)))
    }
}

const NEIGHBOUR_CACHE_MAX_TRY: usize = 3;

impl NetworkLayer {
    pub fn send_and_receive(
        src_ip: Ipv4Addr,
        dest_ip: Ipv4Addr,
        payload_buffer: &[u8],
        layers: Layer,
        val: u8,
    ) -> Result<(Option<Vec<u8>>, Option<Duration>)> {
        let mut dest_loopback = false;
        // Determine the destination MAC address.
        let dest_mac = if NetworkLayer::is_dest_ip_local(dest_ip) {
            println!("Local network.");
            // Local network.
            // Check if the packet is destined for the local network.
            if dest_ip == src_ip || dest_ip.is_loopback() {
                dest_loopback = true;
                MacAddr::zero()
            } else {
                // Check the ARP cache to see if the MAC address is already known.
                match Arp::search_neighbor_cache(dest_ip.into())? {
                    Some(mac) => mac, // Found in the ARP cache.
                    None => {
                        // Send an ARP request.
                        println!("ARP request needed.");
                        let mut mac_addr: Option<MacAddr> = None;

                        // Attempt to retrieve the MAC address via ARP.
                        for _ in 0..NEIGHBOUR_CACHE_MAX_TRY {
                            match Arp::send_request(src_ip, dest_ip)? {
                                (Some(mac), _) => {
                                    mac_addr = Some(mac);
                                    break;
                                }
                                (None, _) => (),
                            }
                        }

                        // Return the MAC address.
                        match mac_addr {
                            Some(mac) => mac,
                            None => return Err(CantFindMacAddress.into()),
                        }
                    }
                }
            }
        } else {
            println!("Remote network.");
            // Remote network.
            // Retrieve the IP address of the default gateway.
            let router_ip = NetworkLayer::system_route()?;
            // Retrieve the mac address of the default gateway.
            match Arp::search_neighbor_cache(router_ip.into())? {
                Some(mac) => mac, // Found in the ARP cache.
                None => {
                    // Send an ARP request.
                    let mut mac: Option<MacAddr> = None;
                    for _ in 0..NEIGHBOUR_CACHE_MAX_TRY {
                        match Arp::send_request(src_ip, router_ip)? {
                            (Some(mac_addr), _) => {
                                mac = Some(mac_addr);
                                break;
                            }
                            (None, _) => (),
                        }
                    }

                    match mac {
                        Some(mac) => mac,
                        None => return Err(CantFindMacAddress.into()),
                    }
                }
            }
        };

        let interface = if dest_loopback {
            match Interface::from_loopback() {
                Some(interface) => interface,
                None => return Err(CantFindInterface.into()),
            }
        } else {
            match Interface::from_ip(src_ip) {
                Some(interface) => interface,
                None => return Err(CantFindInterface.into()),
            }
        };

        // Send the packet over the datalink layer.
        let (response, rtt) = DatalinkLayer::send_and_receive(
            interface,
            dest_mac,
            EtherTypes::Ipv4,
            payload_buffer,
            layers,
            val,
        )?;

        // Pass up the response to the caller.
        match response {
            Some(layer_2_packet) => Ok((Some(layer_2_packet), rtt)),
            None => Ok((None, None)),
        }
    }

    /// Determines if the destination IP address is local to the network.
    pub fn is_dest_ip_local(dest_ip: Ipv4Addr) -> bool {
        for interface in datalink::interfaces() {
            for ip_network in interface.ips {
                if ip_network.contains(dest_ip.into()) {
                    return true;
                }
            }
        }
        false
    }

    /// Retrieves the IP address of the default gateway.
    pub fn system_route() -> Result<Ipv4Addr> {
        if cfg!(target_os = "windows") {
            let command = Command::new("powershell")
                .args(["route", "print"])
                .output()?;
            let output = String::from_utf8_lossy(&command.stdout);
            let lines: Vec<&str> = output.split("\n").filter(|v| v.len() > 0).collect();
            for line in lines {
                if line.contains("0.0.0.0") {
                    let l_split: Vec<&str> = line.split(" ").filter(|v| v.len() > 0).collect();
                    let route_ip: Ipv4Addr = l_split[2].parse()?;
                    return Ok(route_ip);
                }
            }
        }
        Err(CantFindRouterAddress.into())
    }
}