use anyhow::Result;
use serde::Deserialize;
use std::{fs, net::IpAddr};
use subnetwork::Ipv4Pool;

#[derive(Deserialize)]
pub struct Input {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub port_numbers: Vec<u16>,
    pub ip_addresses: Vec<String>,
    pub timeout: u64,
}

pub fn load_config(path: &str) -> Result<Input> {
    let data = fs::read(path)?;
    let text = String::from_utf8(data)?;
    let input: Input = toml::from_str(&text)?;
    Ok(input)
}

pub fn parse_ip_addresses(ip_strs: Vec<String>) -> Result<Vec<IpAddr>> {
    let mut ip_addresses = Vec::new();
    for ip_str in ip_strs {
        if ip_str.contains('/') {
            let subnet = Ipv4Pool::from(&ip_str)?;
            ip_addresses.extend(subnet.map(IpAddr::V4));
        } else {
            ip_addresses.push(ip_str.parse()?);
        }
    }
    Ok(ip_addresses)
}
