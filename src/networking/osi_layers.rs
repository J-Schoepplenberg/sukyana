use super::interface::Interface;
use crate::{
    errors::{ChannelError, ScannerError},
    networking::arp::Arp,
};
use anyhow::Result;
use pnet::{
    datalink::{self, Channel, NetworkInterface},
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
const NEIGHBOR_CACHE_MAX_TRY: usize = 3;

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

                if ipv4_packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                    TcpPacket::new(ipv4_packet.payload())
                        .map(|tcp| (tcp.get_source(), tcp.get_destination()))
                } else {
                    None
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
    /// Creates an Ethernet packet.
    pub fn build_ethernet_packet(
        src_mac: MacAddr,
        dest_mac: MacAddr,
        ethertype: EtherType,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut ethernet_buffer = [0u8; ETHERNET_BUFFER_SIZE];
        let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

        ethernet_packet.set_source(src_mac);
        ethernet_packet.set_destination(dest_mac);
        ethernet_packet.set_ethertype(ethertype);
        ethernet_packet.set_payload(payload);

        ethernet_buffer[..(ETHERNET_HEADER_SIZE + payload.len())].to_vec()
    }

    /// Sends a packet over a data link channel and waits 3 seconds for a response.
    ///
    /// Processes the ethernet frames in the channel and matches them against the provided layer data.
    ///
    /// Returns a matching response and the round-trip time.
    pub fn send_and_receive(
        interface: NetworkInterface,
        dest_mac: MacAddr,
        ethernet_type: EtherType,
        packet: &[u8],
        layers: Layer,
        val: u16,
    ) -> Result<(Option<Vec<u8>>, Duration)> {
        let channel = datalink::channel(&interface, Default::default())?;

        let (mut sender, mut receiver) = match channel {
            Channel::Ethernet(tx, rx) => (tx, rx),
            _ => return Err(ChannelError::UnexpectedChannelType.into()),
        };

        let src_mac = if dest_mac == MacAddr::zero() {
            MacAddr::zero()
        } else {
            interface.mac.ok_or(ScannerError::CantFindMacAddress)?
        };

        let ethernet_packet =
            DatalinkLayer::build_ethernet_packet(src_mac, dest_mac, ethernet_type, packet);

        let send_time = Instant::now();

        sender
            .send_to(&ethernet_packet, Some(interface))
            .ok_or(ChannelError::SendError)??;

        let timeout = Duration::from_secs(5);
        
        let mut response_buffer = None;
        while send_time.elapsed() < timeout {
            if let Ok(response) = receiver.next() {
                if layers.match_layer(response) {
                    response_buffer = Some(response.to_vec());
                    break;
                }
            }
        }

        let rtt = send_time.elapsed();

        Ok((response_buffer, rtt))
    }
}

impl NetworkLayer {
    /// Determines the MAC address of `dest_ip` and which interface to use.
    ///
    /// The packet is handed over to the data link layer.
    ///
    /// Returns the response and the round-trip time.
    pub fn send_and_receive(
        src_ip: Ipv4Addr,
        dest_ip: Ipv4Addr,
        packet: &[u8],
        layers: Layer,
        val: u16,
    ) -> Result<(Option<Vec<u8>>, Duration)> {
        let dest_mac = NetworkLayer::get_dest_mac_addres(src_ip, dest_ip)?;

        let interface = if NetworkLayer::is_dest_ip_loopback(src_ip, dest_ip) {
            Interface::from_loopback().ok_or(ScannerError::CantFindInterface)?
        } else {
            Interface::from_ip(src_ip).ok_or(ScannerError::CantFindInterface)?
        };

        let (response, rtt) = DatalinkLayer::send_and_receive(
            interface,
            dest_mac,
            EtherTypes::Ipv4,
            packet,
            layers,
            val,
        )?;

        Ok((response, rtt))
    }

    /// Attempts to determine the MAC address of the given `dest_ip`.
    ///
    /// If `dest_ip` is local, the MAC address is set to zero or resolved using the system's ARP cache.
    ///
    /// Otherwise, returns the resolved MAC address of the default gateway.
    pub fn get_dest_mac_addres(src_ip: Ipv4Addr, dest_ip: Ipv4Addr) -> Result<MacAddr> {
        if NetworkLayer::is_dest_ip_local(dest_ip) {
            if NetworkLayer::is_dest_ip_loopback(src_ip, dest_ip) {
                Ok(MacAddr::zero())
            } else {
                NetworkLayer::resolve_mac_address(src_ip, dest_ip)
            }
        } else {
            let router_ip = NetworkLayer::get_default_route_ip()?;
            NetworkLayer::resolve_mac_address(src_ip, router_ip)
        }
    }

    /// Attempts to resolve the MAC address of the given `dest_ip`.
    ///
    /// First searches the system's ARP cache, then sends an ARP request if the MAC address is not found.
    pub fn resolve_mac_address(src_ip: Ipv4Addr, dest_ip: Ipv4Addr) -> Result<MacAddr> {
        Arp::search_neighbor_cache(dest_ip.into())?
            .or_else(|| {
                (0..NEIGHBOR_CACHE_MAX_TRY).find_map(|_| {
                    Arp::send_request(src_ip, dest_ip)
                        .ok()
                        .and_then(|(mac, _)| mac)
                })
            })
            .ok_or(ScannerError::CantFindMacAddress.into())
    }

    /// Check if `dest_ip` and `src_ip` are the same or if `dest_ip` is a loopback address.
    pub fn is_dest_ip_loopback(src_ip: Ipv4Addr, dest_ip: Ipv4Addr) -> bool {
        dest_ip == src_ip || dest_ip.is_loopback()
    }

    /// Determines if the destination IP address is local to the network.
    pub fn is_dest_ip_local(dest_ip: Ipv4Addr) -> bool {
        if dest_ip.is_loopback() {
            return true;
        }
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
    pub fn get_default_route_ip() -> Result<Ipv4Addr> {
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
        Err(ScannerError::CantFindRouterAddress.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::networking::tcp::Tcp;
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
        Err(ScannerError::CantFindRouterAddress.into())
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
        let tcp_packet_1 = Tcp::build_syn_packet(src_ip, src_port, dest_ip, dest_port);
        let ethernet_packet_1 =
            DatalinkLayer::build_ethernet_packet(src_mac, dest_mac, ethertype, &tcp_packet_1);
        assert!(transport_layer.match_packet(&ethernet_packet_1));

        // The packet should not match anymore since src_ip and dest_port are different.
        let tcp_packet_2 =
            Tcp::build_syn_packet(Ipv4Addr::new(10, 0, 0, 1), src_port, dest_ip, 443);
        let ethernet_packet_2 =
            DatalinkLayer::build_ethernet_packet(src_mac, dest_mac, ethertype, &tcp_packet_2);
        assert!(!transport_layer.match_packet(&ethernet_packet_2));
    }

    #[test]
    fn test_get_dest_mac_address() {
        // Test with a local IP address.
        let src_ip = Ipv4Addr::new(127, 0, 0, 1);
        let dest_ip = Ipv4Addr::new(127, 0, 0, 1);
        let mac = NetworkLayer::get_dest_mac_addres(src_ip, dest_ip);
        assert!(mac.is_ok());
        assert_eq!(mac.unwrap(), MacAddr::zero());

        // Test with a non-local IP address.
        let dest_ip_remote = Ipv4Addr::new(8, 8, 8, 8);
        let mac_remote = NetworkLayer::get_dest_mac_addres(src_ip, dest_ip_remote);
        assert!(mac_remote.is_ok());
        assert_ne!(mac_remote.unwrap(), MacAddr::zero());
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
