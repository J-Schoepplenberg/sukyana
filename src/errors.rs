use std::{
    error::Error,
    fmt::{Display, Formatter, Result},
};

/// Error type for when a data link (layer 2) channel cannot be created.
#[derive(Debug)]
pub struct CreateDatalinkChannelFailed;

impl Error for CreateDatalinkChannelFailed {}

impl Display for CreateDatalinkChannelFailed {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "Creating the data link channel failed.")
    }
}

/// Error type for when a MAC address cannot be found.
#[derive(Debug)]
pub struct CantFindMacAddress;

impl Error for CantFindMacAddress {}

impl Display for CantFindMacAddress {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "Cannot find a MAC address.")
    }
}

/// Error type for when an interface cannot be found.
#[derive(Debug)]
pub struct CantFindInterface;

impl Error for CantFindInterface {}

impl Display for CantFindInterface {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "Cannot find an interface.")
    }
}

/// Error type for when a router address cannot be found.
#[derive(Debug)]
pub struct CantFindRouterAddress;

impl Error for CantFindRouterAddress {}

impl Display for CantFindRouterAddress {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(f, "Cannot find a router address.")
    }
}

/// Error type for when a data link channel encounters an error.
#[derive(Debug)]
pub enum ChannelError {
    UnexpectedChannelType,
    SendError,
}

impl Error for ChannelError {}

impl Display for ChannelError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            ChannelError::UnexpectedChannelType => write!(f, "Unexpected channel type"),
            ChannelError::SendError => write!(f, "Send error"),
        }
    }
}
