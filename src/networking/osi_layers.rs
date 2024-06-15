use super::interface::Interface;
use crate::{
    errors::{
        CantFindInterface, CantFindMacAddress, CantFindRouterAddress, CreateDatalinkChannelFailed,
    },
    networking::arp::Arp,
};
use anyhow::Result;
use pnet::{
    datalink::{self, DataLinkReceiver, DataLinkSender, NetworkInterface},
    packet::{
        arp::ArpPacket,
        ethernet::{EtherType, EtherTypes, EthernetPacket, MutableEthernetPacket},
        ip::IpNextHeaderProtocols,
        ipv4::Ipv4Packet,
        tcp::TcpPacket,
        Packet,
    },
    util::MacAddr,
};
use std::{
    net::{IpAddr, Ipv4Addr},
    process::Command,
    time::{Duration, Instant},
};

// Constants based on the operating system.
cfg_if::cfg_if! {
    if #[cfg(target_os = "windows")] {
        const ROUTE_COMMAND: &str = "powershell";
        const ROUTE_ARGS: [&str; 2] = ["route", "print"];
        const ROUTE_INDICATOR: &str = "0.0.0.0";
    } else if #[cfg(target_os = "linux")] {
        const ROUTE_COMMAND: &str = "bash";
        const ROUTE_ARGS: [&str; 1] = ["-c ip route"];
        const ROUTE_INDICATOR: &str = "default";
    } else {
        compile_error!("Unsupported operating system");
    }
}

const ETHERNET_BUFFER_SIZE: usize = 4096;
const ETHERNET_HEADER_SIZE: usize = 14;
const NEIGHBOUR_CACHE_MAX_TRY: usize = 3;

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
    /// Matches the packet at the datalink layer.
    ///
    /// Checks for the source and destination MAC addresses and the Ethernet type.
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
    /// First matches at the data link layer, then checks the source and destination IP addresses.
    ///
    /// Only matches IPv4 packets.
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
        
        println!("Matched at data link layer.");

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
        packet: &[u8],
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
        ethernet_packet.set_payload(packet);

        // Start the timer.
        let send_time = Instant::now();

        // Construct the final payload.
        let final_packet =
            ethernet_buffer[..(ETHERNET_HEADER_SIZE + packet.len())].to_vec();

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

impl NetworkLayer {
    pub fn send_and_receive(
        src_ip: Ipv4Addr,
        dest_ip: Ipv4Addr,
        packet: &[u8],
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
            Interface::from_loopback().ok_or(CantFindInterface)?
        } else {
            Interface::from_ip(src_ip).ok_or(CantFindInterface)?
        };

        // Send the packet over the datalink layer.
        let (response, rtt) = DatalinkLayer::send_and_receive(
            interface,
            dest_mac,
            EtherTypes::Ipv4,
            packet,
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
        datalink::interfaces().iter().any(|interface| {
            interface
                .ips
                .iter()
                .any(|ip_network| ip_network.contains(IpAddr::V4(dest_ip)))
        })
    }

    /// Retrieves the IP address of the default gateway.
    ///
    /// Issues a `Command` to get the system's routing table.
    ///
    /// The output from the launched program is parsed to find the default route.
    pub fn system_route() -> Result<Ipv4Addr> {
        let output = Command::new(ROUTE_COMMAND).args(&ROUTE_ARGS).output()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let lines = stdout.lines();
        for line in lines {
            if line.contains(ROUTE_INDICATOR) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() > 2 {
                    let route_ip: Ipv4Addr = parts[2].parse()?;
                    return Ok(route_ip);
                }
            }
        }
        Err(CantFindRouterAddress.into())
    }
}

#[cfg(test)]
mod tests {
    use pnet::packet::{ipv4::MutableIpv4Packet, FromPacket};

    use super::*;
    use std::{os::windows::process::ExitStatusExt, process::Output};

    fn mock_system_route(output: Output, route: &str) -> Result<Ipv4Addr> {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let lines = stdout.lines();
        for line in lines {
            if line.contains(route) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() > 2 {
                    let route_ip: Ipv4Addr = parts[2].parse()?;
                    return Ok(route_ip);
                }
            }
        }
        Err(CantFindRouterAddress.into())
    }

    #[test]
    fn test_data_link_layer_match() {
        // Set up the data link layer.
        let src_mac = MacAddr::new(0, 1, 2, 3, 4, 5);
        let dest_mac = MacAddr::new(6, 7, 8, 9, 10, 11);
        let ethertype = EtherTypes::Ipv4;
        let layer = DatalinkLayer {
            src_mac: Some(src_mac),
            dest_mac: Some(dest_mac),
            ethernet_type: Some(ethertype),
        };

        // Create an Ethernet packet from the packet_buffer.
        let mut packet_buffer = [0u8; 42];
        let mut eth_packet = MutableEthernetPacket::new(&mut packet_buffer).unwrap();

        // Set the packet fields.
        eth_packet.set_source(src_mac);
        eth_packet.set_destination(dest_mac);
        eth_packet.set_ethertype(ethertype);

        // Ensure the packet matches the layer.
        assert!(layer.match_packet(&eth_packet.packet()));

        // Change the source MAC address.
        eth_packet.set_source(MacAddr::new(1, 2, 3, 4, 5, 6));

        // Ensure the packet does not match the layer anymore.
        assert!(!layer.match_packet(&eth_packet.packet()));
    }

    #[test]
    fn test_network_layer_match() {
        // Set up the data link layer.
        let src_mac = MacAddr::new(0, 1, 2, 3, 4, 5);
        let dest_mac = MacAddr::new(6, 7, 8, 9, 10, 11);
        let ethertype = EtherTypes::Ipv4;
        let datalink_layer = DatalinkLayer {
            src_mac: Some(src_mac),
            dest_mac: Some(dest_mac),
            ethernet_type: Some(ethertype),
        };

        // Set up the network layer.
        let src_ip = Ipv4Addr::new(192, 168, 0, 1);
        let dest_ip = Ipv4Addr::new(192, 168, 0, 2);
        let network_layer = NetworkLayer {
            datalink_layer: Some(datalink_layer),
            src_addr: Some(IpAddr::V4(src_ip)),
            dest_addr: Some(IpAddr::V4(dest_ip)),
        };

        // Create IPv4 header.
        let mut ipv4_packet = [0u8; 20];
        let mut ipv4_header = MutableIpv4Packet::new(&mut ipv4_packet).unwrap();
        ipv4_header.set_source(src_ip);
        ipv4_header.set_destination(dest_ip);
        ipv4_header.set_destination(dest_ip);

        // Create Ethernet packet.
        let mut ethernet_buffer = [0u8; ETHERNET_BUFFER_SIZE];
        let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
        ethernet_packet.set_destination(dest_mac);
        ethernet_packet.set_source(src_mac);
        ethernet_packet.set_ethertype(ethertype);
        ethernet_packet.set_payload(&ipv4_packet);

        // Create the final packet.
        let final_packet = ethernet_buffer[..(ETHERNET_HEADER_SIZE + ipv4_packet.len())].to_vec();

        // Ensure the packet matches both layers.
        assert!(network_layer.match_packet(&final_packet));

        /* let mut packet_data_invalid = [0u8; 42];
        {
            let mut eth_packet = MutableEthernetPacket::new(&mut packet_data_invalid).unwrap();
            eth_packet.set_source(src_mac); 
            eth_packet.set_destination(dest_mac);
            eth_packet.set_ethertype(ethertype);

            let mut ipv4_packet = MutableIpv4Packet::new(&mut eth_packet.packet()).unwrap();
            ipv4_packet.set_source(Ipv4Addr::new(10, 0, 0, 1));
            ipv4_packet.set_destination(dest_ip);
        }

        assert!(!network_layer.match_packet(&packet_data_invalid)); */
    }

    #[test]
    fn test_system_route_windows() {
        // Mock output for Windows format.
        let mock_output = "\
            ===========================================================================
            Interface List
             15...00 1c 42 2b 60 5a ......Intel(R) Ethernet Connection
              1...........................Software Loopback Interface 1
              ===========================================================================
            IPv4 Route Table
            ===========================================================================
            Active Routes:
            Network Destination        Netmask          Gateway       Interface  Metric
                    0.0.0.0          0.0.0.0     192.168.1.1    192.168.1.100    25
                    127.0.0.0        255.0.0.0      On-link        127.0.0.1    306
                    127.0.0.1  255.255.255.255      On-link        127.0.0.1    306
                    127.255.255.255  255.255.255.255      On-link        127.0.0.1    306
            ===========================================================================
            ";

        // Simulate the command output.
        let output = Output {
            stdout: mock_output.as_bytes().to_vec(),
            stderr: vec![],
            status: std::process::ExitStatus::from_raw(0),
        };

        // Mock the system route function.
        let route_ip = mock_system_route(output, "0.0.0.0").unwrap();
        assert_eq!(route_ip, Ipv4Addr::new(192, 168, 1, 1));
    }

    #[test]
    fn test_system_route_linux() {
        // Mock output for Linux format.
        let mock_output = "\
            default via 192.168.1.1 dev eth0 proto static
            192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.100 metric 100
            192.168.1.0/24 dev wlan0 proto kernel scope link src 192.168.1.101 metric 600
            192.168.1.0/24 dev wlan0 proto static scope link metric 100
            ";

        // Simulate the command output.
        let output = Output {
            stdout: mock_output.as_bytes().to_vec(),
            stderr: vec![],
            status: std::process::ExitStatus::from_raw(0),
        };

        // Mock the system route function.
        let route_ip = mock_system_route(output, "default").unwrap();
        assert_eq!(route_ip, Ipv4Addr::new(192, 168, 1, 1));
    }
}
