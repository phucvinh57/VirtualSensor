use std::convert::{Into, TryFrom, TryInto};
use std::net::IpAddr;
use std::ops::{Add, AddAssign};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{fmt, num};

use serde::Serialize;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
pub struct Uid(u128);

impl Uid {
    pub fn New(uid: usize) -> Self {
        Self(uid.try_into().unwrap())
    }
    pub fn ToUsize(&self) -> usize {
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
    pub fn New(gid: usize) -> Self {
        Self(gid.try_into().unwrap())
    }
    pub fn ToUsize(&self) -> usize {
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
    pub fn New(inode: usize) -> Self {
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
    pub fn New() -> Self {
        Self(0)
    }

    pub fn GetCurrentTimestamp() -> Self {
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

    pub fn New() -> Self {
        Self(0)
    }
    pub fn FromSeconds(seconds: usize) -> Self {
        Self((seconds * Self::NANOSECONDS_PER_SECOND).try_into().unwrap())
    }
    pub fn FromMilliSeconds(milliSeconds: usize) -> Self {
        Self(
            (milliSeconds * Self::NANOSECONDS_PER_MILLISECOND)
                .try_into()
                .unwrap(),
        )
    }
    pub fn FromMicroSeconds(microSeconds: usize) -> Self {
        Self(
            (microSeconds * Self::NANOSECONDS_PER_MICROSECOND)
                .try_into()
                .unwrap(),
        )
    }
    pub fn FromNanoSeconds(nanoSeconds: usize) -> Self {
        Self(nanoSeconds.try_into().unwrap())
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
    pub fn FromByte(byte: usize) -> Self {
        Self(byte as u128)
    }
    pub fn FromKB(kb: usize) -> Self {
        Self(kb as u128 * 1024)
    }
    pub fn FromMB(mb: usize) -> Self {
        Self(mb as u128 * 1024 * 1024)
    }
    pub fn FromGB(gb: usize) -> Self {
        Self(gb as u128 * 1024 * 1024 * 1024)
    }
    pub fn FromTB(tb: usize) -> Self {
        Self(tb as u128 * 1024 * 1024 * 1024 * 1024)
    }
    pub fn FromPB(pb: usize) -> Self {
        Self(pb as u128 * 1024 * 1024 * 1024 * 1024 * 1024)
    }
    pub fn FromEB(eb: usize) -> Self {
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
    pub fn New(count: usize) -> Self {
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
    LITTLE,
    BIG,
}

pub fn AlignBuffer(buf: &mut Vec<u8>, align: usize) {
    let paddingLen = ((buf.len() + align - 1) / align) * align - buf.len();
    buf.append(&mut vec![0u8; paddingLen]);
}

pub fn NextAlignNumber(currentNumber: usize, align: usize) -> usize {
    ((currentNumber + align - 1) / align) * align
}

pub fn ParseHexString(input: &str, endian: Endian) -> Result<Vec<u8>, CommonError> {
    if input.len() % 2 != 0 {
        return Err(CommonError::ODD_LENGTH_HEX_STRING(input.len()));
    }

    match endian {
        Endian::LITTLE => (0..input.len())
            .step_by(2)
            .rev()
            .map(|index| {
                u8::from_str_radix(&input[index..index + 2], 16)
                    .map_err(|err| CommonError::PARSE_INT_ERROR(err))
            })
            .collect(),
        Endian::BIG => (0..input.len())
            .step_by(2)
            .map(|index| {
                u8::from_str_radix(&input[index..index + 2], 16)
                    .map_err(|err| CommonError::PARSE_INT_ERROR(err))
            })
            .collect(),
    }
}

#[derive(Debug)]
pub enum CommonError {
    ODD_LENGTH_HEX_STRING(usize),
    PARSE_INT_ERROR(num::ParseIntError),
    CONVERT_ERROR(String),
}

impl std::error::Error for CommonError {}

impl fmt::Display for CommonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let result = match self {
            Self::ODD_LENGTH_HEX_STRING(len) => {
                String::from(format!("Odd length hex string: {}", len))
            }
            Self::PARSE_INT_ERROR(error) => String::from(format!("Parse integer error: {}", error)),
            Self::CONVERT_ERROR(string) => String::from(format!("Can't convert {}", string)),
        };

        write!(f, "{}", result)
    }
}

impl From<num::ParseIntError> for CommonError {
    fn from(error: num::ParseIntError) -> Self {
        Self::PARSE_INT_ERROR(error)
    }
}

pub fn AddressInNetwork(
    addr: &IpAddr,
    networkAddr: &IpAddr,
    networkMask: &IpAddr,
) -> Result<bool, ()> {
    // convert

    // check if they are same kind of address
    match (addr, networkAddr, networkMask) {
        (IpAddr::V4(addr), IpAddr::V4(networkAddr), IpAddr::V4(networkMask)) => {
            // covert them to byte array
            let addr = addr.octets();
            let networkAddr = networkAddr.octets();
            let networkMask = networkMask.octets();

            // compare byte-by-byte
            for i in 0..addr.len() {
                if addr[i] & networkMask[i] != networkAddr[i] & networkMask[i] {
                    return Ok(false);
                }
            }

            Ok(true)
        }
        (IpAddr::V6(addr), IpAddr::V6(networkAddr), IpAddr::V6(networkMask)) => {
            // covert them to byte array
            let addr = addr.octets();
            let networkAddr = networkAddr.octets();
            let networkMask = networkMask.octets();

            // compare byte-by-byte
            for i in 0..addr.len() {
                if addr[i] & networkMask[i] != networkAddr[i] & networkMask[i] {
                    return Ok(false);
                }
            }

            Ok(true)
        }
        _ => Err(()),
    }
}
