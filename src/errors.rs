use thiserror::Error;

#[derive(Error, Debug)]
pub enum ScannerError {
    #[error("Cannot find a router address.")]
    CantFindRouterAddress,
    #[error("Cannot find an interface.")]
    CantFindInterface,
    #[error("Cannot find a MAC address.")]
    CantFindMacAddress,
    #[error("Cannot create an Ethernet packet.")]
    CantCreateEthernetPacket,
    #[error("Cannot create an IPv4 packet.")]
    CantCreateIpv4Packet,
    #[error("Cannot create a TCP packet.")]
    CantCreateTcpPacket,
}

#[derive(Error, Debug)]
pub enum ChannelError {
    #[error("Unexpected channel type")]
    UnexpectedChannelType,
    #[error("Send error")]
    SendError,
}
