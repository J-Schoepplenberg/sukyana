use env_logger::{Builder, WriteStyle};
use output::{save_arp_results, save_icmp_results, save_port_scan_results};
use scanner::scanner::{ScanMethod, Scanner};
use subnetwork::Ipv4Pool;
use std::net::{IpAddr, Ipv4Addr};
mod errors;
mod networking;
mod scanner;
use log::{error, info};
mod output;

#[tokio::main]
async fn main() {
    Builder::from_default_env()
        .write_style(WriteStyle::Always)
        .filter_level(log::LevelFilter::Trace)
        .init();

    let my_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 178, 26));
    let my_port = 99;

    //let ip_addresses = vec![IpAddr::V4(Ipv4Addr::new(142, 251, 209, 131))];
    //let ip_addresses = vec![IpAddr::V4(Ipv4Addr::new(142, 250, 184, 238))];
    //let ip_addresses = vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))];
    //let ip_addresses = vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))];
    //let ip_addresses = vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))];
    //let ip_addresses = vec![IpAddr::V4(Ipv4Addr::new(76, 76, 2, 0)), IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))];
    //let ip_addresses = vec![IpAddr::V4(Ipv4Addr::new(37, 187, 205, 99))];
    let port_numbers = vec![22, 80, 443, 8080, 8081];
    let subnet = Ipv4Pool::from("192.168.178.0/24").unwrap();
    let mut ip_addresses = Vec::new();
    for ip in subnet {
        ip_addresses.push(IpAddr::V4(ip));
    }
    //let ip_addresses = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 178, 26))];
    //let port_numbers = vec![53];
    let timeout = std::time::Duration::from_secs(1);

    let hosts = Scanner::scan(ScanMethod::TcpSyn, my_ip, my_port, &ip_addresses, &port_numbers, timeout).await;
    
    match save_port_scan_results(hosts).await {
        Ok(path) => info!("Port scan results saved to: {}.", path),
        Err(e) => error!("Failed to save port scan results: {}", e),
    }
    
    /* let hosts = Scanner::ping(my_ip, ip_addresses, timeout).await;
    
    match save_icmp_results(hosts).await {
        Ok(path) => info!("ICMP scan results saved to: {}.", path),
        Err(e) => error!("Failed to save ICMP scan results: {}", e),
    } */

    /* let hosts = Scanner::arp(my_ip, ip_addresses, timeout).await;

    match save_arp_results(hosts).await {
        Ok(path) => info!("ARP scan results saved to: {}.", path),
        Err(e) => error!("Failed to save ARP scan results: {}", e),
    } */
}