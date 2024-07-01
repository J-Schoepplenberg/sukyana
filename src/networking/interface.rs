use crate::errors::ScannerError;
use anyhow::Result;
use netdev::{get_default_interface, ip::Ipv4Net, NetworkDevice};
use pnet::util::MacAddr;
use std::net::Ipv4Addr;

// Constants based on the operating system.
cfg_if::cfg_if! {
    if #[cfg(target_os = "windows")] {
        const NAME_PREFIX: &str = "\\Device\\NPF_";
    } else if #[cfg(target_os = "linux")] {
        const NAME_PREFIX: &str = "";
    } else {
        compile_error!("Unsupported operating system.");
    }
}

const MAX_INTERFACE_NAME_LENTGH: usize = 256;

/// Represents a network interface with an IP address, MAC address, and gateway.
///
/// Retrieving the list of all interfaces in every tokio task to determine which
/// interface to use is very expensive, therefore we get the interface already
/// ahead of time for all tasks for performance reasons.
///
/// Later we need to convert the struct to `pnet::datalink::NetworkInterface`.
///
/// To store the name we use the fact that the maximum length of an interface name is
/// 256 bytes on Windows (`MAX_ADAPTER_NAME_LENGTH`) and 16 bytes on Linux (`IFNAMSIZ`).
/// This enables us to store the name in a fixed-size array and makes it possible to
/// easily pass the struct around.
#[derive(Clone, Copy, Debug)]
pub struct Interface {
    pub index: u32,
    pub name: [u8; MAX_INTERFACE_NAME_LENTGH],
    pub ip: Ipv4Net,
    pub mac: MacAddr,
    pub flags: u32,
    pub gateway: Gateway,
}

impl Interface {
    /// Creates a new `Interface` struct.
    ///
    /// May fail if the default interface, router address, MAC address or gateway can't be found.
    pub fn new() -> Result<Self> {
        let interface = get_default_interface()
            .ok()
            .ok_or(ScannerError::CantFindInterface)?;
        let ip = *interface
            .ipv4
            .first()
            .ok_or(ScannerError::CantFindInterfaceIp)?;
        let mac = interface
            .mac_addr
            .ok_or(ScannerError::CantFindInterfaceMac)?;
        let name = Interface::string_to_fixed_bytes(&interface.name);
        let gateway = Gateway::new(interface.gateway)?;
        let iface = Interface {
            index: interface.index,
            name,
            ip,
            mac: convert_mac_address(mac),
            flags: interface.flags,
            gateway,
        };
        Ok(iface)
    }

    /// Converts a string to a fixed-size 256 byte array.
    pub fn string_to_fixed_bytes(s: &str) -> [u8; MAX_INTERFACE_NAME_LENTGH] {
        let mut bytes = [0u8; MAX_INTERFACE_NAME_LENTGH];
        let len = s.len().min(MAX_INTERFACE_NAME_LENTGH);
        bytes[..len].copy_from_slice(&s.as_bytes()[..len]);
        bytes
    }

    /// Converts a fixed-size 256 byte array to a string.
    pub fn fixed_bytes_to_string(bytes: &[u8; MAX_INTERFACE_NAME_LENTGH]) -> String {
        let len = bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(MAX_INTERFACE_NAME_LENTGH);
        String::from_utf8_lossy(&bytes[..len]).to_string()
    }

    /// Converts `Interface` to `pnet::datalink::NetworkInterface`.
    pub fn convert_interface(&self) -> Result<pnet::datalink::NetworkInterface> {
        Ok(pnet::datalink::NetworkInterface {
            index: self.index,
            name: format!(
                "{}{}",
                NAME_PREFIX,
                Interface::fixed_bytes_to_string(&self.name)
            ),
            description: String::new(),
            mac: Some(self.mac),
            ips: vec![pnet::ipnetwork::IpNetwork::V4(
                pnet::ipnetwork::Ipv4Network::new(self.ip.addr, self.ip.prefix_len)?,
            )],
            flags: self.flags,
        })
    }
}

/// Represents a gateway which is associated with an interface.
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub struct Gateway {
    pub ip: Ipv4Addr,
    pub mac: MacAddr,
}

impl Gateway {
    pub fn new(gateway: Option<NetworkDevice>) -> Result<Self> {
        let gateway = gateway.ok_or(ScannerError::CantFindGateway)?;
        let ip = gateway
            .ipv4
            .first()
            .ok_or(ScannerError::CantFindGatewayIp)?;
        let mac = convert_mac_address(gateway.mac_addr);
        Ok(Gateway { ip: *ip, mac })
    }
}

/// Converts `netdev::mac::MacAddr` to `pnet::util::MacAddr`.
pub fn convert_mac_address(mac: netdev::mac::MacAddr) -> pnet::util::MacAddr {
    pnet::util::MacAddr(mac.0, mac.1, mac.2, mac.3, mac.4, mac.5)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert_string_and_bytes() {
        let input = "7BE5B259-D1B8-452D-A891-5CDBE6A95988";
        let bytes = Interface::string_to_fixed_bytes(input);
        let string = Interface::fixed_bytes_to_string(&bytes);
        assert_eq!(input, string);
    }
}
