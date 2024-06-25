use anyhow::Result;
use serde::Deserialize;
use std::{fs, net::IpAddr};
use subnetwork::Ipv4Pool;

#[derive(Deserialize, Debug)]
pub struct Input {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub port_numbers: Vec<String>,
    pub ip_addresses: Vec<String>,
    pub timeout: u64,
    pub number_of_packets: usize,
    pub should_randomize_ports: bool,
}

pub fn load_config(path: &str) -> Result<Input> {
    let data = fs::read(path)?;
    let text = String::from_utf8(data)?;
    let input: Input = toml::from_str(&text)?;
    Ok(input)
}

pub fn parse_port_numbers(ports: Vec<String>) -> Result<Vec<u16>> {
    let mut port_numbers = Vec::new();
    for port in ports {
        if port.contains('-') {
            let range = port.split('-').collect::<Vec<&str>>();
            let start = range[0].parse::<u16>()?;
            let end = range[1].parse::<u16>()?;
            port_numbers.extend(start..=end);
        } else {
            port_numbers.push(port.parse()?);
        }
    }
    Ok(port_numbers)
}

pub fn parse_ip_addresses(ips: Vec<String>) -> Result<Vec<IpAddr>> {
    let mut ip_addresses = Vec::new();
    for ip in ips {
        if ip.contains('/') {
            let subnet = Ipv4Pool::from(&ip)?;
            ip_addresses.extend(subnet.map(IpAddr::V4));
        } else {
            ip_addresses.push(ip.parse()?);
        }
    }
    Ok(ip_addresses)
}
