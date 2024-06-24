use anyhow::Result;
use clap::{Parser, Subcommand};
use env_logger::{Builder, WriteStyle};
use input::{load_config, parse_ip_addresses};
use networking::interface::Interface;
use output::{save_arp_results, save_icmp_results, save_port_scan_results};
use scanner::engine::{ScanMethod, Scanner};
mod errors;
mod networking;
mod scanner;
use log::{error, info};
mod input;
mod output;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(long)]
    config: String,
    /// Retrieve MAC addresses of hosts via ARP.
    #[arg(long)]
    arp: bool,
    /// Ping hosts with ICMP echo requests.
    #[arg(long)]
    ping: bool,
    /// Subcommands.
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan ports on hosts.
    Scan {
        /// TCP SYN scan.
        #[arg(long)]
        tcp_syn: bool,
        /// TCP connect scan.
        #[arg(long)]
        tcp_connect: bool,
        /// TCP ACK scan.
        #[arg(long)]
        tcp_ack: bool,
        /// TCP FIN scan.
        #[arg(long)]
        tcp_fin: bool,
        /// TCP XMAS scan.
        #[arg(long)]
        tcp_xmas: bool,
        /// TCP NULL scan.
        #[arg(long)]
        tcp_null: bool,
        /// TCP window scan.
        #[arg(long)]
        tcp_window: bool,
        /// TCP Maimon scan.
        #[arg(long)]
        tcp_maimon: bool,
        /// UDP scan.
        #[arg(long)]
        udp: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    Builder::from_default_env()
        .write_style(WriteStyle::Always)
        .filter_level(log::LevelFilter::Trace)
        .init();

    let args = Cli::parse();
    let input = load_config(&args.config)?;

    let interface = Interface::new()?;

    let src_ip = input.src_ip;
    let src_port = input.src_port;

    let timeout = std::time::Duration::from_secs(input.timeout);

    let port_numbers = input.port_numbers;
    let ip_addresses = parse_ip_addresses(input.ip_addresses)?;

    if let Some(command) = &args.command {
        match command {
            Commands::Scan {
                tcp_syn,
                tcp_connect,
                tcp_ack,
                tcp_fin,
                tcp_xmas,
                tcp_null,
                tcp_window,
                tcp_maimon,
                udp,
            } => {
                let scan_methods = vec![
                    (*tcp_syn, ScanMethod::TcpSyn),
                    (*tcp_connect, ScanMethod::TcpConnect),
                    (*tcp_ack, ScanMethod::TcpAck),
                    (*tcp_fin, ScanMethod::TcpFin),
                    (*tcp_xmas, ScanMethod::TcpXmas),
                    (*tcp_null, ScanMethod::TcpNull),
                    (*tcp_window, ScanMethod::TcpWindow),
                    (*tcp_maimon, ScanMethod::TcpMaimon),
                    (*udp, ScanMethod::Udp),
                ];

                for (enabled, method) in scan_methods {
                    if enabled {
                        let hosts = Scanner::scan(
                            interface,
                            method,
                            src_ip,
                            src_port,
                            &ip_addresses,
                            &port_numbers,
                            timeout,
                        )
                        .await;
                        match save_port_scan_results(hosts).await {
                            Ok(path) => info!("Port scan results saved to: {}.", path),
                            Err(e) => error!("Failed to save port scan results: {}", e),
                        }
                    }
                }
            }
        }
    }

    if args.ping {
        let hosts = Scanner::ping(interface, src_ip, ip_addresses.clone(), timeout).await;
        match save_icmp_results(hosts).await {
            Ok(path) => info!("ICMP scan results saved to: {}.", path),
            Err(e) => error!("Failed to save ICMP scan results: {}", e),
        }
    }

    if args.arp {
        let hosts = Scanner::arp(interface, src_ip, ip_addresses, timeout).await;
        match save_arp_results(hosts).await {
            Ok(path) => info!("ARP scan results saved to: {}.", path),
            Err(e) => error!("Failed to save ARP scan results: {}", e),
        }
    }

    Ok(())
}
