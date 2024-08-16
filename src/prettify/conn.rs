use std::{fmt::Debug, net::IpAddr};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Dynamic {
    client: IpAddr,
    server: IpAddr,
}

impl Dynamic {
    pub fn new(client: IpAddr, server: IpAddr) -> Self {
        Self { client, server }
    }

    pub fn direction(&self, src: IpAddr, dst: IpAddr) -> Direction {
        if self.client == src && self.server == dst {
            Direction::REQUEST
        } else if self.server == src && self.client == dst {
            Direction::RESPONSE
        } else {
            Direction::EXTERNAL
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum Direction {
    REQUEST,
    RESPONSE,
    EXTERNAL,
}
impl Debug for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::REQUEST => "REQUEST",
            Self::RESPONSE => "RESPONSE",
            Self::EXTERNAL => "EXTERNAL",
        };

        if cfg!(not(feature = "color")) {
            write!(f, "{name}")
        } else {
            let color = match self {
                Self::REQUEST => "33",
                Self::RESPONSE => "36",
                Self::EXTERNAL => "30",
            };
            write!(f, "\x1b[1;{color}m{name}\x1b[0m")
        }
    }
}
