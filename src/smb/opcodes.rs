use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

#[repr(u16)]
#[derive(Debug, Clone, Eq, PartialEq)]
#[derive(FromPrimitive)]
pub enum Opcodes {
    NegotiateProtocol = 0x00,
    SessionSetup = 0x01,
    SessionLogoff = 0x02,
    TreeConnect = 0x03,
    TreeDisconnect = 0x04,
    Create = 0x05,
    Close = 0x06,
    Flush = 0x07,
    Read = 0x08,
    Write = 0x09,
    Lock = 0x0a,
    Ioctl = 0x0b,
    Cancel = 0x0c,
    KeepAlive = 0x0d,
    Find = 0x0e,
    Notify = 0x0f,
    GetInfo = 0x10,
    SetInfo = 0x11,
    Break = 0x12,
    // Only in ASYNC, prevs are SYNC
    //Server2ClientNotif = 0x13,
}

pub enum Error {
    UnknownOpcode,
}

impl TryFrom<u16> for Opcodes {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        FromPrimitive::from_u16(value).ok_or(Self::Error::UnknownOpcode)
    }
}
