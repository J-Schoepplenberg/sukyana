use itertools::{iproduct, Product};
use std::net::{IpAddr, SocketAddr};

/// An iterator that produces all combinations of the given IP addresses and ports.
pub struct SocketIterator<'a> {
    /// A product iterator over slices of IP addresses and ports.
    pub socket_iterator: Product<std::slice::Iter<'a, IpAddr>, std::slice::Iter<'a, u16>>,
}

impl<'a> SocketIterator<'a> {
    /// Creates a new `SocketIterator` from slices of IP addresses and ports.
    pub fn new(ip_addresses: &'a [IpAddr], port_numbers: &'a [u16]) -> Self {
        Self {
            socket_iterator: iproduct!(ip_addresses.iter(), port_numbers.iter()),
        }
    }
}

impl<'a> Iterator for SocketIterator<'a> {
    type Item = SocketAddr;

    /// Advances the iterator and returns the next `SocketAddr` combination.
    fn next(&mut self) -> Option<Self::Item> {
        self.socket_iterator
            .next()
            .map(|(ip, port)| SocketAddr::new(*ip, *port))
    }
}

#[cfg(test)]
mod tests {
    use super::SocketIterator;
    use std::{
        net::{IpAddr, SocketAddr},
        str::FromStr,
    };

    #[test]
    fn empty_ips() {
        let ip_addresses = vec![];
        let port_numbers = vec![22, 80, 443];
        let mut socket_iterator = SocketIterator::new(&ip_addresses, &port_numbers);

        // Since there are no IPs, the iterator should be exhausted immediately.
        assert_eq!(socket_iterator.next(), None);
    }

    #[test]
    fn empty_ports() {
        let ip_addresses = vec![
            IpAddr::from_str("127.0.0.1").unwrap(),
            IpAddr::from_str("192.168.0.1").unwrap(),
        ];
        let port_numbers = vec![];
        let mut socket_iterator = SocketIterator::new(&ip_addresses, &port_numbers);

        // Since there are no ports, the iterator should be exhausted immediately.
        assert_eq!(socket_iterator.next(), None);
    }

    #[test]
    fn ip_port_combinations() {
        let ip_addresses = vec![
            IpAddr::from_str("127.0.0.1").unwrap(),
            IpAddr::from_str("192.168.0.1").unwrap(),
        ];
        let port_numbers = vec![22, 80, 443];
        let mut socket_iterator = SocketIterator::new(&ip_addresses, &port_numbers);

        let expected_sockets = vec![
            SocketAddr::new(IpAddr::from_str("127.0.0.1").unwrap(), 22),
            SocketAddr::new(IpAddr::from_str("127.0.0.1").unwrap(), 80),
            SocketAddr::new(IpAddr::from_str("127.0.0.1").unwrap(), 443),
            SocketAddr::new(IpAddr::from_str("192.168.0.1").unwrap(), 22),
            SocketAddr::new(IpAddr::from_str("192.168.0.1").unwrap(), 80),
            SocketAddr::new(IpAddr::from_str("192.168.0.1").unwrap(), 443),
        ];

        // Ensure iterator produces all expected combinations.
        for socket in expected_sockets {
            assert_eq!(socket_iterator.next(), Some(socket));
        }

        // Ensure iterator is exhausted.
        assert_eq!(socket_iterator.next(), None);
    }
}
