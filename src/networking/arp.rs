use super::{
    interface::Interface,
    osi_layers::{DatalinkLayer, Layer, NetworkLayer},
};
use crate::errors::{CantFindInterface, CantFindMacAddress};
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
    time::Duration,
};

pub struct Arp;

impl Arp {
    /// Sends an ARP request to retrieve MAC address.
    pub fn send_request(
        src_ip: Ipv4Addr,
        dest_ip: Ipv4Addr,
    ) -> Result<(Option<MacAddr>, Option<Duration>)> {
        // Get the interface that matches the source IP address.
        let interface = match Interface::from_ip(src_ip) {
            Some(interface) => interface,
            None => return Err(CantFindInterface.into()),
        };

        // Get the MAC address of the source.
        let src_mac = match interface.mac {
            Some(mac) => mac,
            None => return Err(CantFindMacAddress.into()),
        };

        // Create the ARP packet.
        let mut arp_buffer = [0u8; 28];
        let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

        // Set the ARP packet fields.
        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(ArpOperations::Request);
        arp_packet.set_sender_hw_addr(src_mac);
        arp_packet.set_sender_proto_addr(src_ip);
        arp_packet.set_target_hw_addr(MacAddr::zero());
        arp_packet.set_target_proto_addr(dest_ip);

        // Set the ethertype for the Ethernet frame.
        let ethernet_type = EtherTypes::Arp;

        // Create the match data for layer 2.
        let data_link_layer = DatalinkLayer {
            src_mac: None,
            dest_mac: None,
            ethernet_type: Some(ethernet_type),
        };

        // Create the match data for layer 3.
        let network_layer = NetworkLayer {
            datalink_layer: Some(data_link_layer),
            src_addr: Some(dest_ip.into()),
            dest_addr: Some(src_ip.into()),
        };

        // Matches from layer 3 to layer 2.
        let layer = Layer::Three(network_layer);

        // Send the ARP packet over the datalink layer.
        let (response, rtt) = DatalinkLayer::send_and_receive(
            interface,
            MacAddr::broadcast(),
            ethernet_type,
            &arp_buffer,
            layer,
            0,
        )?;

        // Extract the MAC address from the ARP response.
        match response {
            Some(response_buffer) => Ok((Arp::get_mac_address(&response_buffer), rtt)),
            None => Ok((None, None)),
        }
    }
    /// Searches the ARP cache to retrieve the MAC address of the given IP address.
    pub fn search_neighbor_cache(ip_addr: IpAddr) -> Result<Option<MacAddr>> {
        let respone = Arp::neighbor_cache()?;
        match respone {
            Some(map) => {
                for (ip, mac) in map {
                    if ip == ip_addr {
                        return Ok(Some(mac));
                    }
                }
                Ok(None)
            }
            None => Ok(None),
        }
    }

    /// The neighbor cache, also known as the ARP cache.
    ///
    /// Retrieves the information of each on-link neighbor.
    ///
    /// Includes the IP address and MAC address of each neighbor.
    pub fn neighbor_cache() -> Result<Option<HashMap<IpAddr, MacAddr>>> {
        if cfg!(target_os = "windows") {
            let command = Command::new("powershell")
                .args(["Get-NetNeighbor"])
                .output()?;
            let output = String::from_utf8_lossy(&command.stdout);
            let lines: Vec<&str> = output.split("\r\n").filter(|v| v.len() > 0).collect();
            let mut ret: HashMap<IpAddr, MacAddr> = HashMap::new();
            for line in lines[2..].to_vec() {
                let l_split: Vec<&str> = line.split(" ").filter(|v| v.len() > 0).collect();
                if l_split.len() >= 5 {
                    let ip_str = l_split[1];
                    let mac_str = l_split[2].replace("-", ":");
                    let ip: IpAddr = ip_str.parse()?;
                    let mac: MacAddr = mac_str.parse()?;
                    ret.insert(ip, mac);
                }
            }
            return Ok(Some(ret));
        } else {
            Ok(None)
        }
    }

    /// Extracts the MAC address from an ARP packet.
    pub fn get_mac_address(packet: &[u8]) -> Option<MacAddr> {
        let response = EthernetPacket::new(packet)?;
        println!("{:?}", response);
        println!("{:?}", response.get_ethertype());
        match response.get_ethertype() {
            EtherTypes::Arp => {
                let arp_packet = ArpPacket::new(response.payload())?;
                Some(arp_packet.get_sender_hw_addr())
            }
            _ => None, // Not an ARP packet.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_send_request() -> Result<()> {
        let src_ip = Ipv4Addr::new(192, 168, 178, 26);
        let router_ip = NetworkLayer::system_route()?;
        // TODO: Implement ARP layer matching.
        let (response, rtt) = Arp::send_request(src_ip, router_ip).unwrap();
        assert!(response.is_some());
        assert!(rtt.is_some());
        Ok(())
    }

    #[test]
    fn test_search_neighbor_cache() -> Result<()> {
        let router_ip = IpAddr::V4(NetworkLayer::system_route()?);
        let result = Arp::search_neighbor_cache(router_ip).unwrap();
        assert!(result.is_some());
        Ok(())
    }
}
