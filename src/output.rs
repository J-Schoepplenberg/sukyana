use crate::{errors::ScannerError, scanner::engine::ScanResult};
use anyhow::Result;
use pnet::util::MacAddr;
use std::{env, io::Write, net::{IpAddr, SocketAddr}, time::Duration};
use tokio::{fs::File, io::AsyncWriteExt};

pub trait ToCsv {
    fn header() -> &'static str;
    fn to_csv(&self) -> String;
}

impl ToCsv for (SocketAddr, ScanResult, Duration) {
    fn header() -> &'static str {
        "Socket,Status,RTT"
    }

    fn to_csv(&self) -> String {
        format!("{},{:?},{:?}", self.0, self.1, self.2)
    }
}

impl ToCsv for (IpAddr, ScanResult, Duration) {
    fn header() -> &'static str {
        "IP Address,Status,RTT"
    }

    fn to_csv(&self) -> String {
        format!("{},{:?},{:?}", self.0, self.1, self.2)
    }
}

impl ToCsv for (IpAddr, MacAddr, Duration) {
    fn header() -> &'static str {
        "IP Address,MAC Address,RTT"
    }

    fn to_csv(&self) -> String {
        format!("{},{:?},{:?}", self.0, self.1, self.2)
    }
}

pub async fn save_scan_results<T: ToCsv>(hosts: Vec<T>, file_name: &str) -> Result<String> {
    let output_path = env::current_dir()?.join(file_name);
    let mut file = File::create(&output_path).await?;

    let mut buffer = Vec::new();
    writeln!(buffer, "{}", T::header())?;
    for host in hosts {
        writeln!(buffer, "{}", host.to_csv())?;
    }

    file.write_all(&buffer).await?;

    output_path
        .to_str()
        .map(String::from)
        .ok_or_else(|| ScannerError::CouldNotWriteResults.into())
}

pub async fn save_port_scan_results(hosts: Vec<(SocketAddr, ScanResult, Duration)>) -> Result<String> {
    save_scan_results(hosts, "port_scan_results.csv").await
}

pub async fn save_icmp_results(hosts: Vec<(IpAddr, ScanResult, Duration)>) -> Result<String> {
    save_scan_results(hosts, "icmp_scan_results.csv").await
}

pub async fn save_arp_results(hosts: Vec<(IpAddr, MacAddr, Duration)>) -> Result<String> {
    save_scan_results(hosts, "arp_scan_results.csv").await
}
