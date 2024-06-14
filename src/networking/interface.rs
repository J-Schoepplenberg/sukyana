use pnet::datalink::{self, NetworkInterface};
use std::net::{IpAddr, Ipv4Addr};

/// Provides methods for finding network interfaces.
pub struct Interface;

impl Interface {
    /// Attempts to find the network interface that has the given IP address.
    pub fn from_ip(src_ip: Ipv4Addr) -> Option<NetworkInterface> {
        for interface in datalink::interfaces() {
            for ip in &interface.ips {
                match ip.ip() {
                    IpAddr::V4(ipv4) => {
                        if ipv4 == src_ip {
                            return Some(interface);
                        }
                    }
                    _ => (),
                }
            }
        }
        None
    }

    // Attempts to find the network interface that has the loopback IP address.
    pub fn from_loopback() -> Option<NetworkInterface> {
        for interface in datalink::interfaces() {
            for ip in &interface.ips {
                match ip.ip() {
                    IpAddr::V4(ipv4) => {
                        if ipv4.is_loopback() {
                            return Some(interface);
                        }
                    }
                    _ => (),
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_from_ip_found() {
        let local_ip = Ipv4Addr::new(192, 168, 178, 26);
        let interface = Interface::from_ip(local_ip);

        // Ensure the interface is found.
        assert!(
            interface.is_some(),
            "Expected to find an interface with IP {}.",
            local_ip
        );

        // Ensure the interface contains the expected IP address.
        assert_eq!(
            interface
                .unwrap()
                .ips
                .iter()
                .any(|ip| ip.ip() == IpAddr::V4(local_ip)),
            true,
            "The found interface does not contain the expected IP address."
        );
    }

    #[test]
    fn test_from_ip_not_found() {
        let unlikely_ip = Ipv4Addr::new(203, 0, 113, 1);
        let interface = Interface::from_ip(unlikely_ip);

        // Ensure the interface is not found.
        assert!(
            interface.is_none(),
            "Expected not to find an interface with IP {}",
            unlikely_ip
        );
    }
}
