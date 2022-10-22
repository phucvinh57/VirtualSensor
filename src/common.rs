use std::convert::{Into, TryFrom, TryInto};
use std::net::IpAddr;
use std::ops::{Add, AddAssign};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{fmt, num};

use serde::Serialize;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
pub struct Uid(u128);

impl Uid {
    pub fn new(uid: usize) -> Self {
        Self(uid.try_into().unwrap())
    }
    pub fn to_usize(&self) -> usize {
        self.0.try_into().unwrap()
    }
}

impl TryFrom<&str> for Uid {
    type Error = CommonError;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        Ok(Self(input.parse()?))
    }
}

impl Into<u32> for Uid {
    fn into(self) -> u32 {
        self.0.try_into().unwrap()
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
pub struct Gid(u128);

impl Gid {
    pub fn new(gid: usize) -> Self {
        Self(gid.try_into().unwrap())
    }
    pub fn to_usize(&self) -> usize {
        self.0.try_into().unwrap()
    }
}

impl TryFrom<&str> for Gid {
    type Error = CommonError;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        Ok(Self(input.parse()?))
    }
}

impl Into<u32> for Gid {
    fn into(self) -> u32 {
        self.0.try_into().unwrap()
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
pub struct Inode(u128);

impl Inode {
    pub fn new(inode: usize) -> Self {
        Self(inode.try_into().unwrap())
    }
}

impl TryFrom<&str> for Inode {
    type Error = CommonError;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        Ok(Self(input.parse()?))
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
pub struct Timestamp(u128);

impl Timestamp {
    pub fn new() -> Self {
        Self(0)
    }

    pub fn get_curr_timestamp() -> Self {
        Self(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        )
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
// save nano seconds
pub struct TimeCount(u128);

impl TimeCount {
    const NANOSECONDS_PER_SECOND: usize = 1_000_000_000;
    const NANOSECONDS_PER_MILLISECOND: usize = 1_000_000;
    const NANOSECONDS_PER_MICROSECOND: usize = 1_000;

    pub fn new() -> Self {
        Self(0)
    }
    pub fn from_secs(seconds: usize) -> Self {
        Self((seconds * Self::NANOSECONDS_PER_SECOND).try_into().unwrap())
    }
    pub fn from_milisecs(millisecs: usize) -> Self {
        Self(
            (millisecs * Self::NANOSECONDS_PER_MILLISECOND)
                .try_into()
                .unwrap(),
        )
    }
    pub fn from_microsecs(microsecs: usize) -> Self {
        Self(
            (microsecs * Self::NANOSECONDS_PER_MICROSECOND)
                .try_into()
                .unwrap(),
        )
    }
    pub fn from_nanosecs(nanosecs: usize) -> Self {
        Self(nanosecs.try_into().unwrap())
    }
}

impl Add<Self> for TimeCount {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self(self.0 + other.0)
    }
}

impl AddAssign<Self> for TimeCount {
    fn add_assign(&mut self, other: Self) {
        self.0 += other.0;
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
// save bytes
pub struct DataCount(u128);

impl DataCount {
    pub fn from_byte(byte: usize) -> Self {
        Self(byte as u128)
    }
    pub fn from_kb(kb: usize) -> Self {
        Self(kb as u128 * 1024)
    }
    pub fn from_mb(mb: usize) -> Self {
        Self(mb as u128 * 1024 * 1024)
    }
    pub fn from_gb(gb: usize) -> Self {
        Self(gb as u128 * 1024 * 1024 * 1024)
    }
    pub fn from_tb(tb: usize) -> Self {
        Self(tb as u128 * 1024 * 1024 * 1024 * 1024)
    }
    pub fn from_pb(pb: usize) -> Self {
        Self(pb as u128 * 1024 * 1024 * 1024 * 1024 * 1024)
    }
    pub fn from_eb(eb: usize) -> Self {
        Self(eb as u128 * 1024 * 1024 * 1024 * 1024 * 1024 * 1024)
    }
}

impl Add<Self> for DataCount {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self(self.0 + other.0)
    }
}

impl AddAssign<Self> for DataCount {
    fn add_assign(&mut self, other: Self) {
        self.0 += other.0;
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
pub struct Count(u128);

impl Count {
    pub fn new(count: usize) -> Self {
        Self(count as u128)
    }
}

impl Add<Self> for Count {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self(self.0 + other.0)
    }
}

impl AddAssign<Self> for Count {
    fn add_assign(&mut self, other: Self) {
        self.0 += other.0;
    }
}

pub enum Endian {
    Little,
    Big,
}

pub fn align_buffer(buf: &mut Vec<u8>, align: usize) {
    let padding_len = ((buf.len() + align - 1) / align) * align - buf.len();
    buf.append(&mut vec![0u8; padding_len]);
}

pub fn next_align_num(curr_num: usize, align: usize) -> usize {
    ((curr_num + align - 1) / align) * align
}

pub fn parse_hex_str(input: &str, endian: Endian) -> Result<Vec<u8>, CommonError> {
    if input.len() % 2 != 0 {
        return Err(CommonError::OddLenHexStr(input.len()));
    }

    match endian {
        Endian::Little => (0..input.len())
            .step_by(2)
            .rev()
            .map(|index| {
                u8::from_str_radix(&input[index..index + 2], 16)
                    .map_err(|err| CommonError::ParseIntErr(err))
            })
            .collect(),
        Endian::Big => (0..input.len())
            .step_by(2)
            .map(|index| {
                u8::from_str_radix(&input[index..index + 2], 16)
                    .map_err(|err| CommonError::ParseIntErr(err))
            })
            .collect(),
    }
}

#[derive(Debug)]
pub enum CommonError {
    OddLenHexStr(usize),
    ParseIntErr(num::ParseIntError),
    ConvertErr(String),
}

impl std::error::Error for CommonError {}

impl fmt::Display for CommonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let result = match self {
            Self::OddLenHexStr(len) => String::from(format!("Odd length hex string: {}", len)),
            Self::ParseIntErr(error) => String::from(format!("Parse integer error: {}", error)),
            Self::ConvertErr(string) => String::from(format!("Can't convert {}", string)),
        };

        write!(f, "{}", result)
    }
}

impl From<num::ParseIntError> for CommonError {
    fn from(error: num::ParseIntError) -> Self {
        Self::ParseIntErr(error)
    }
}

pub fn addr_in_network(addr: &IpAddr, net_addr: &IpAddr, net_mask: &IpAddr) -> Result<bool, ()> {
    // check if they are same kind of address
    
    match (addr, net_addr, net_mask) {
        (IpAddr::V4(addr), IpAddr::V4(net_addr), IpAddr::V4(net_mask)) => {
            // covert them to byte array
            let addr = addr.octets();
            let net_addr = net_addr.octets();
            let net_mask = net_mask.octets();
            
            // compare byte-by-byte
            for i in 0..addr.len() {
                if addr[i] & net_mask[i] != net_addr[i] & net_mask[i] {
                    return Ok(false);
                }
            }

            Ok(true)
        }
        (IpAddr::V6(addr), IpAddr::V6(net_addr), IpAddr::V6(net_mask)) => {
            // covert them to byte array
            let addr = addr.octets();
            let net_addr = net_addr.octets();
            let net_mask = net_mask.octets();

            // compare byte-by-byte
            for i in 0..addr.len() {
                if addr[i] & net_mask[i] != net_addr[i] & net_mask[i] {
                    return Ok(false);
                }
            }

            Ok(true)
        }
        _ => Err(()),
    }
}
