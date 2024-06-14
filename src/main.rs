use env_logger::{Builder, WriteStyle};
use networking::tcp::Tcp;
use std::net::Ipv4Addr;
mod errors;
mod networking;

fn syn() {
    let src_ip = Ipv4Addr::new(192, 168, 178, 26);
    let src_port = 99;
    let dest_ip = Ipv4Addr::new(142, 251, 209, 131);
    let dest_port = 80;
    Tcp::send_syn_packet(0, src_ip, src_port, dest_ip, dest_port);
}

async fn syn_tcp_scan(value: u8) {
    let src_ip = Ipv4Addr::new(127, 0, 0, 1);
    let src_port = 99;
    let dest_ip = Ipv4Addr::new(127, 0, 0, 1);
    let dest_port = 5354;
    tokio::task::spawn_blocking(move || {
        Tcp::send_syn_packet(value, src_ip, src_port, dest_ip, dest_port)
    })
    .await
    .unwrap();
}

#[tokio::main]
async fn main() {
    Builder::from_default_env()
        .write_style(WriteStyle::Always)
        .filter_level(log::LevelFilter::Trace)
        .init();

    syn();

    /* let num_calls = 3;
    let mut handles = Vec::new();

    for i in 0..num_calls {
        let handle = tokio::spawn(async move {
            syn_tcp_scan(i).await
        });
        handles.push(handle);
    }

    join_all(handles).await; */
}
