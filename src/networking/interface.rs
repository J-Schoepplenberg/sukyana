use pnet::datalink::{self, NetworkInterface};
use std::net::{IpAddr, Ipv4Addr};

/// Provides methods for finding network interfaces.
pub struct Interface;

impl Interface {
    /// Generalized method to find a network interface by a predicate.
    fn find_interface<P>(predicate: P) -> Option<NetworkInterface>
    where
        P: Fn(&Ipv4Addr) -> bool,
    {
        datalink::interfaces().into_iter().find(|interface| {
            interface.ips.iter().any(|ip| match ip.ip() {
                IpAddr::V4(ipv4) => predicate(&ipv4),
                _ => false,
            })
        })
    }

    /// Attempts to find the network interface that has the given IP address.
    pub fn from_ip(src_ip: Ipv4Addr) -> Option<NetworkInterface> {
        Self::find_interface(|&ipv4| ipv4 == src_ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_from_ip_found() {
        // Local interface IP address.
        let local_ip = Ipv4Addr::new(192, 168, 178, 26);
        let interface = Interface::from_ip(local_ip);

        // Ensure the interface is found.
        assert!(interface.is_some());

        // Ensure the interface contains the expected IP address.
        let contained = interface
            .unwrap()
            .ips
            .iter()
            .any(|ip| ip.ip() == IpAddr::V4(local_ip));
        assert_eq!(contained, true);
    }

    #[test]
    fn test_from_ip_not_found() {
        // IP address unlikely to be found on a local network.
        let unlikely_ip = Ipv4Addr::new(203, 0, 113, 1);
        let interface = Interface::from_ip(unlikely_ip);

        // Ensure the interface is not found.
        assert!(interface.is_none());
    }
}
