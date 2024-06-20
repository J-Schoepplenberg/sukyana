use env_logger::{Builder, WriteStyle};
use scanner::scanner::{ScanMethod, Scanner};
use std::net::{IpAddr, Ipv4Addr};
mod errors;
mod networking;
mod scanner;

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
    let ip_addresses = vec![IpAddr::V4(Ipv4Addr::new(76, 76, 2, 0)), IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))];
    //let ip_addresses = vec![IpAddr::V4(Ipv4Addr::new(37, 187, 205, 99))];
    //let port_numbers = vec![22, 80, 443, 8080, 8081];
    let port_numbers = vec![53];
    let timeout = std::time::Duration::from_secs(5);

    Scanner::scan(ScanMethod::Udp, my_ip, my_port, &ip_addresses, &port_numbers, timeout).await;
    //Scanner::ping(my_ip, ip_addresses, timeout).await;
}