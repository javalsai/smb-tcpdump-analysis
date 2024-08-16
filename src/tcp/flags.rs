use std::{
    fmt::{Binary, Debug},
    ops::{BitAnd, BitOr, BitXor, Not},
};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum FlagError {
    InvalidFlagChar(char),
}

pub trait FlagMask {
    fn as_flag_bits(self) -> u8;
    fn as_flags(self) -> FlagCollection;
}

#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, EnumIter)]
pub enum Flag {
    FIN = 1,
    SYN = 2,
    RST = 4,
    PSH = 8,
    ACK = 16,
    URG = 32,
    ECE = 64,
    CWR = 128,
}

impl FlagMask for Flag {
    fn as_flag_bits(self) -> u8 {
        self as u8
    }

    fn as_flags(self) -> FlagCollection {
        FlagCollection::from(self)
    }
}

impl Flag {
    pub fn to_char(&self) -> char {
        match self {
            Flag::FIN => 'F',
            Flag::SYN => 'S',
            Flag::RST => 'R',
            Flag::PSH => 'P',
            Flag::ACK => '.',
            Flag::URG => 'U',
            Flag::ECE => 'E',
            Flag::CWR => 'C',
        }
    }

    pub fn from_char(c: char) -> Result<Self, FlagError> {
        match c {
            'F' => Ok(Self::FIN),
            'S' => Ok(Self::SYN),
            'R' => Ok(Self::RST),
            'P' => Ok(Self::PSH),
            '.' => Ok(Self::ACK),
            'U' => Ok(Self::URG),
            'E' => Ok(Self::ECE),
            'C' => Ok(Self::CWR),
            _ => Err(FlagError::InvalidFlagChar(c)),
        }
    }
}

impl TryFrom<char> for Flag {
    type Error = FlagError;
    fn try_from(value: char) -> Result<Self, Self::Error> {
        Self::from_char(value)
    }
}

impl From<Flag> for char {
    fn from(value: Flag) -> Self {
        value.to_char()
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct FlagCollection(u8);

impl FlagCollection {
    pub fn new() -> Self {
        Self(0)
    }

    // TODO: make fn without '['/']' check and another with char[] to be ignored
    pub fn try_parse(str: &'_ str) -> Result<Self, FlagError> {
        let mut flags = Self::new();
        for flag in str.chars().map(Flag::from_char) {
            match flag {
                Ok(flag) => flags.set(flag),
                Err(FlagError::InvalidFlagChar(c)) => {
                    if c != '[' && c != ']' {
                        return Err(FlagError::InvalidFlagChar(c));
                    }
                }
            }
        }
        Ok(flags)
    }

    pub fn set(&mut self, flag: impl FlagMask) {
        self.0 |= flag.as_flag_bits();
    }

    pub fn unset(&mut self, flag: impl FlagMask) {
        self.0 &= !flag.as_flag_bits();
    }

    pub fn is_set(&self, flag: impl FlagMask) -> bool {
        let flag_bits = flag.as_flag_bits();
        (self.0 & flag_bits) == flag_bits
    }

    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }

    pub fn from_bits(raw: u8) -> Self {
        Self(raw)
    }

    pub fn human_str(&self) -> String {
        let mut flags_str = String::new();
        for flag in Flag::iter() {
            if self.is_set(flag) {
                flags_str.push(flag.to_char());
            }
        }
        flags_str
    }
}

impl FlagMask for FlagCollection {
    fn as_flag_bits(self) -> u8 {
        self.0
    }
    fn as_flags(self) -> FlagCollection {
        self
    }
}

impl From<Flag> for FlagCollection {
    fn from(value: Flag) -> Self {
        FlagCollection(value as u8)
    }
}

impl Debug for FlagCollection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.human_str())
    }
}
impl Binary for FlagCollection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:08b}", self.0)
    }
}

impl BitAnd for FlagCollection {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self::Output {
        FlagCollection(self.0 & rhs.0)
    }
}
impl BitOr for FlagCollection {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        FlagCollection(self.0 | rhs.0)
    }
}
impl BitXor for FlagCollection {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self::Output {
        FlagCollection(self.0 ^ rhs.0)
    }
}
impl Not for FlagCollection {
    type Output = FlagCollection;
    fn not(self) -> <Self as Not>::Output {
        FlagCollection(!self.0)
    }
}
