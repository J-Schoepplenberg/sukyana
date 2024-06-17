use crate::errors::ScannerError;

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
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    process::Command,
    str::FromStr,
    time::Duration,
};

// Constants based on the operating system.
cfg_if::cfg_if! {
    if #[cfg(target_os = "windows")] {
        const NEIGHBOR_COMMAND: &str = "powershell";
        const NEIGHBOR_ARGS: [&str; 1] = ["Get-NetNeighbor"];
        const IP_INDEX: usize = 1;
        const MAC_INDEX: usize = 2;
        const SKIP: usize = 2;
    } else if #[cfg(target_os = "linux")] {
        const NEIGHBOR_COMMAND: &str = "bash";
        const NEIGHBOR_ARGS: [&str; 1] = ["-c ip neighbour"];
        const IP_INDEX: usize = 0;
        const MAC_INDEX: usize = 4;
        const SKIP: usize = 0;
    } else {
        compile_error!("Unsupported operating system");
    }
}

pub struct Arp;

impl Arp {
    /// Constructs an ARP packet.
    /// 
    /// Sets:
    /// - Source MAC address.
    /// - Source IP address.
    /// - Destination IP address.
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

    /// Sends an ARP request to retrieve MAC address.
    /// 
    /// The ARP packet is handed over to the data link layer.
    pub fn send_request(
        src_ip: Ipv4Addr,
        dest_ip: Ipv4Addr,
    ) -> Result<(Option<MacAddr>, Option<Duration>)> {
        let interface = match Interface::from_ip(src_ip) {
            Some(interface) => interface,
            None => return Err(ScannerError::CantFindInterface.into()),
        };

        let src_mac = match interface.mac {
            Some(mac) => mac,
            None => return Err(ScannerError::CantFindMacAddress.into()),
        };

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
            interface,
            MacAddr::broadcast(),
            ethernet_type,
            &arp_packet,
            layer,
            0,
        )?;

        match response {
            Some(packet) => Ok((Arp::get_mac_address(&packet), rtt)),
            None => Ok((None, None)),
        }
    }

    /// Searches the ARP cache to retrieve the MAC address of the given IP address.
    pub fn search_neighbor_cache(ip_addr: IpAddr) -> Result<Option<MacAddr>> {
        let response = Arp::neighbor_cache()?;
        Ok(response.and_then(|map| {
            map.into_iter()
                .find_map(|(ip, mac)| if ip == ip_addr { Some(mac) } else { None })
        }))
    }

    /// Retrieves the neighbor cache (also known as the ARP cache).
    ///
    /// Issues a `Command` to output the neighbor cache and parse it.
    ///
    /// Returns the IP address and MAC address of each on-link neighbor as a `HashMap`.
    pub fn neighbor_cache() -> Result<Option<HashMap<IpAddr, MacAddr>>> {
        let output = Command::new(NEIGHBOR_COMMAND)
            .args(&NEIGHBOR_ARGS)
            .output()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let lines = stdout.lines();
        let mut cache: HashMap<IpAddr, MacAddr> = HashMap::new();
        for line in lines.skip(SKIP) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() > MAC_INDEX {
                if let (Ok(ip), Ok(mac)) = (
                    parts[IP_INDEX].parse(),
                    MacAddr::from_str(&parts[MAC_INDEX].replace('-', ":")),
                ) {
                    cache.insert(ip, mac);
                }
            }
        }
        Ok(Some(cache))
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
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_send_request_and_get_mac() -> Result<()> {
        // Local interface IP address.
        let src_ip = Ipv4Addr::new(192, 168, 178, 26);

        // Router IP address.
        let router_ip = NetworkLayer::get_default_route_ip()?;

        // Send an ARP request to the router. Parses the MAC address from the response.
        let (response, rtt) = Arp::send_request(src_ip, router_ip).unwrap();

        // Ensure we received a response and round-trip time.
        assert!(response.is_some());
        assert!(rtt.is_some());
        Ok(())
    }

    #[test]
    fn test_search_neighbor_cache() -> Result<()> {
        // Router IP address.
        let router_ip = IpAddr::V4(NetworkLayer::get_default_route_ip()?);

        // Search the neighbor cache for the router.
        let result = Arp::search_neighbor_cache(router_ip).unwrap();

        // Ensure the router is found in the neighbor cache.
        assert!(result.is_some());
        Ok(())
    }
}
