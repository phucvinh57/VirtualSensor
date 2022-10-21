use std::collections::HashMap;
use std::convert::TryInto;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::{Add, AddAssign};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::{fmt, fs, io};

use pcap::{Capture, Device, Packet, Precision};
use serde::{Serialize, Serializer};

use crate::common::{self, CommonError, Count, DataCount, Endian, Inode};
use crate::config::{self, ConfigError};

const TCP_PAYLOAD_TYPE: u8 = 0x06;
const UDP_PAYLOAD_TYPE: u8 = 0x11;

const nullIpv4: IpAddr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
const nullIpv6: IpAddr = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Serialize)]
pub enum ConnectionType {
    TCP,
    UDP,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Serialize)]
pub struct UniConnection {
    srcAddr: IpAddr,
    srcPort: u16,
    desAddr: IpAddr,
    desPort: u16,
    connectionType: ConnectionType,
}

impl UniConnection {
    pub fn New(
        srcAddr: IpAddr,
        srcPort: u16,
        desAddr: IpAddr,
        desPort: u16,
        connectionType: ConnectionType,
    ) -> Self {
        Self {
            srcAddr,
            srcPort,
            desAddr,
            desPort,
            connectionType,
        }
    }

    pub fn SrcAddr(&self) -> IpAddr {
        self.srcAddr
    }

    pub fn SrcPort(&self) -> u16 {
        self.srcPort
    }

    pub fn DesAddr(&self) -> IpAddr {
        self.desAddr
    }

    pub fn DesPort(&self) -> u16 {
        self.desPort
    }

    pub fn ConnectionType(&self) -> ConnectionType {
        self.connectionType
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Serialize)]
pub struct Connection {
    localAddr: IpAddr,
    localPort: u16,
    remoteAddr: IpAddr,
    remotePort: u16,
    connectionType: ConnectionType,
}

impl Connection {
    pub fn New(
        localAddr: IpAddr,
        localPort: u16,
        remoteAddr: IpAddr,
        remotePort: u16,
        connectionType: ConnectionType,
    ) -> Self {
        Self {
            localAddr,
            localPort,
            remoteAddr,
            remotePort,
            connectionType,
        }
    }

    pub fn LocalAddr(&self) -> IpAddr {
        self.localAddr
    }

    pub fn LocalPort(&self) -> u16 {
        self.localPort
    }

    pub fn RemoteAddr(&self) -> IpAddr {
        self.remoteAddr
    }

    pub fn RemotePort(&self) -> u16 {
        self.remotePort
    }

    pub fn ConnectionType(&self) -> ConnectionType {
        self.connectionType
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Serialize)]
pub struct UniConnectionStat {
    uniConnection: UniConnection,

    packetCount: Count,
    totalDataCount: DataCount,
    realDataCount: DataCount,

    #[serde(skip_serializing)]
    isUsed: bool,
}

impl UniConnectionStat {
    pub fn New(uniConnection: UniConnection) -> Self {
        Self {
            uniConnection,

            packetCount: Count::New(0),
            totalDataCount: DataCount::FromByte(0),
            realDataCount: DataCount::FromByte(0),

            isUsed: false,
        }
    }

    pub fn UniConnection(&self) -> UniConnection {
        self.uniConnection
    }

    pub fn PacketCount(&self) -> Count {
        self.packetCount
    }

    pub fn TotalDataCount(&self) -> DataCount {
        self.totalDataCount
    }

    pub fn RealDataCount(&self) -> DataCount {
        self.realDataCount
    }

    fn MarkAsUsed(&mut self) {
        self.isUsed = true;
    }
}

impl Add<Self> for UniConnectionStat {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        assert!(
            self.uniConnection == other.uniConnection,
            "Can't add different uniconnections!"
        );

        Self {
            uniConnection: self.uniConnection,

            packetCount: self.packetCount + other.packetCount,
            totalDataCount: self.totalDataCount + other.totalDataCount,
            realDataCount: self.realDataCount + other.realDataCount,

            isUsed: false,
        }
    }
}

impl AddAssign<Self> for UniConnectionStat {
    fn add_assign(&mut self, other: Self) {
        assert!(
            self.uniConnection == other.uniConnection,
            "Can't add different uniconnections!"
        );

        self.packetCount += other.packetCount;
        self.totalDataCount += other.totalDataCount;
        self.realDataCount += other.realDataCount;
    }
}

#[derive(Debug)]
struct ThreadData {
    device: Device,
    uniConnectionStats: Option<HashMap<UniConnection, UniConnectionStat>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InterfaceRawStat {
    interfaceName: String,
    description: String,

    #[serde(serialize_with = "InterfaceRawStatUniConnectionStatsSerialize")]
    uniConnectionStats: HashMap<UniConnection, UniConnectionStat>,
}

impl InterfaceRawStat {
    pub fn New(interfaceName: String, description: String) -> Self {
        Self {
            interfaceName,
            description,
            uniConnectionStats: HashMap::new(),
        }
    }

    pub fn GetUniConnectionStat(
        &mut self,
        uniConnection: &UniConnection,
    ) -> Option<&UniConnectionStat> {
        self.uniConnectionStats.get_mut(uniConnection).map(|x| {
            x.MarkAsUsed();
            &*x
        })
    }

    pub fn RemoveUsedUniConnectionStats(&mut self) {
        self.uniConnectionStats
            .retain(|_uniConnection, uniConnectionStat| !uniConnectionStat.isUsed);
    }
}

fn InterfaceRawStatUniConnectionStatsSerialize<S: Serializer>(
    input: &HashMap<UniConnection, UniConnectionStat>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(input.values())
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkRawStat {
    #[serde(skip_serializing)]
    connectionLookupTable: HashMap<Inode, Connection>,

    #[serde(skip_serializing)]
    interfaceNameLookupTable: HashMap<Connection, String>,

    #[serde(serialize_with = "NetworkRawStatUniConnectionStatsSerialize")]
    interfaceRawStats: HashMap<String, InterfaceRawStat>,
}

impl NetworkRawStat {
    pub fn New() -> Self {
        Self {
            connectionLookupTable: HashMap::new(),
            interfaceNameLookupTable: HashMap::new(),
            interfaceRawStats: HashMap::new(),
        }
    }

    pub fn LookupConnection(&self, inode: &Inode) -> Option<&Connection> {
        self.connectionLookupTable
            .get(inode)
            .and_then(|connection| Some(connection))
    }

    pub fn LookupInterfaceName(&self, connection: &Connection) -> Option<&str> {
        self.interfaceNameLookupTable
            .get(connection)
            .and_then(|name| Some(name.as_str()))
    }

    pub fn GetInterfaceRawStat(&mut self, interfaceName: &str) -> Option<&mut InterfaceRawStat> {
        self.interfaceRawStats
            .get_mut(interfaceName)
            .and_then(|interfaceRawStat| Some(interfaceRawStat))
    }

    pub fn RemoveUsedUniConnectionStats(&mut self) {
        for (_, interfaceRawStat) in &mut self.interfaceRawStats {
            interfaceRawStat.RemoveUsedUniConnectionStats();
        }
    }
}

fn NetworkRawStatUniConnectionStatsSerialize<S: Serializer>(
    input: &HashMap<String, InterfaceRawStat>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(input.values())
}

fn ParseIpv4Packet(data: &[u8]) -> Result<UniConnectionStat, NetworkStatError> {
    const IPV4_FIXED_HEADER_SIZE: usize = 20;

    // check fixed header len
    if data.len() < IPV4_FIXED_HEADER_SIZE {
        return Err(NetworkStatError::IPV4_PACKET_LENGTH_ERROR(data.len()));
    }

    // check version
    if data[0] & 0xf0 != 0x40
    // not ipv4
    {
        return Err(NetworkStatError::IPV4_PACKET_VERSION_ERROR(data[0] & 0xf0));
    }

    // get header len
    let headerLength = ((data[0] & 0x0f) * 4) as usize;

    // get payload len
    let payloadLength = u16::from_be_bytes(data[2..4].try_into().unwrap()) as usize - headerLength;

    // get payload protocol
    let connectionType = match data[9] {
        TCP_PAYLOAD_TYPE => ConnectionType::TCP,
        UDP_PAYLOAD_TYPE => ConnectionType::UDP,
        _ => return Err(NetworkStatError::UNSUPPORTED_PROTOCOL(data[9])),
    };

    // get src ip begin at data[12]
    let srcAddr = IpAddr::V4(Ipv4Addr::new(data[12], data[13], data[14], data[15]));

    // get des ip begin at data[16]
    let desAddr = IpAddr::V4(Ipv4Addr::new(data[16], data[17], data[18], data[19]));

    // get source port
    let srcPort = u16::from_be_bytes(
        data.get(headerLength..headerLength + 2)
            .ok_or(NetworkStatError::CONVERT_ERROR)?
            .try_into()
            .unwrap(),
    );

    // get des port
    let desPort = u16::from_be_bytes(
        data.get(headerLength + 2..headerLength + 4)
            .ok_or(NetworkStatError::CONVERT_ERROR)?
            .try_into()
            .unwrap(),
    );

    Ok(UniConnectionStat {
        uniConnection: UniConnection::New(srcAddr, srcPort, desAddr, desPort, connectionType),

        packetCount: Count::New(1),
        totalDataCount: DataCount::FromByte(0),
        realDataCount: DataCount::FromByte(payloadLength),

        isUsed: false,
    })
}

fn ParseIpv6Packet(data: &[u8]) -> Result<UniConnectionStat, NetworkStatError> {
    const IPV6_FIXED_HEADER_SIZE: usize = 40;

    // check fixed header len
    if data.len() < IPV6_FIXED_HEADER_SIZE {
        return Err(NetworkStatError::IPV6_PACKET_LENGTH_ERROR(data.len()));
    }

    // check version
    if data[0] & 0xf0 != 0x60
    // not ipv6
    {
        return Err(NetworkStatError::IPV6_PACKET_VERSION_ERROR(data[0] & 0xf0));
    }

    // get payload length
    let payloadLength = u16::from_be_bytes(data[4..6].try_into().unwrap()) as usize;

    // get src ip begin at data[8]
    let a = u16::from_be_bytes(data[8..10].try_into().unwrap());
    let b = u16::from_be_bytes(data[10..12].try_into().unwrap());
    let c = u16::from_be_bytes(data[12..14].try_into().unwrap());
    let d = u16::from_be_bytes(data[14..16].try_into().unwrap());
    let e = u16::from_be_bytes(data[16..18].try_into().unwrap());
    let f = u16::from_be_bytes(data[18..20].try_into().unwrap());
    let g = u16::from_be_bytes(data[20..22].try_into().unwrap());
    let h = u16::from_be_bytes(data[22..24].try_into().unwrap());
    let srcAddr = IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h));

    // get des ip begin at data[24]
    let a = u16::from_be_bytes(data[24..26].try_into().unwrap());
    let b = u16::from_be_bytes(data[26..28].try_into().unwrap());
    let c = u16::from_be_bytes(data[28..30].try_into().unwrap());
    let d = u16::from_be_bytes(data[30..32].try_into().unwrap());
    let e = u16::from_be_bytes(data[32..34].try_into().unwrap());
    let f = u16::from_be_bytes(data[34..36].try_into().unwrap());
    let g = u16::from_be_bytes(data[36..38].try_into().unwrap());
    let h = u16::from_be_bytes(data[38..40].try_into().unwrap());
    let desAddr = IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h));

    // skip through ipv6 extension headers
    let mut nextHeaderType = data[6];
    let mut currentIndex = IPV6_FIXED_HEADER_SIZE;
    let ipv6ExtensionHeaderTypes = [0, 43, 44, 51, 50, 60, 135, 139, 140, 253, 254];
    let normalPayloadTypes = [6, 17];

    loop {
        match nextHeaderType {
            x if normalPayloadTypes.contains(&x) => break,
            x if ipv6ExtensionHeaderTypes.contains(&x) => {
                let tmp = data
                    .get(currentIndex..currentIndex + 2)
                    .ok_or(NetworkStatError::CONVERT_ERROR)?;
                nextHeaderType = tmp[0];
                currentIndex += tmp[1] as usize;
            }
            headerType => {
                return Err(NetworkStatError::IPV6_UNKNOWN_OPTIONAL_HEADER_TYPE(
                    headerType,
                ))
            }
        }
    }

    // get payload protocol
    let connectionType = match nextHeaderType {
        TCP_PAYLOAD_TYPE => ConnectionType::TCP,
        UDP_PAYLOAD_TYPE => ConnectionType::UDP,
        _ => return Err(NetworkStatError::UNSUPPORTED_PROTOCOL(nextHeaderType)),
    };

    // get src port
    let srcPort = u16::from_be_bytes(
        data.get(currentIndex..currentIndex + 2)
            .ok_or(NetworkStatError::CONVERT_ERROR)?
            .try_into()
            .unwrap(),
    );

    // get des port
    let desPort = u16::from_be_bytes(
        data.get(currentIndex + 2..currentIndex + 4)
            .ok_or(NetworkStatError::CONVERT_ERROR)?
            .try_into()
            .unwrap(),
    );

    Ok(UniConnectionStat {
        uniConnection: UniConnection::New(srcAddr, srcPort, desAddr, desPort, connectionType),

        packetCount: Count::New(1),
        totalDataCount: DataCount::FromByte(0),
        realDataCount: DataCount::FromByte(payloadLength - (currentIndex - IPV6_FIXED_HEADER_SIZE)),

        isUsed: false,
    })
}

fn GetUniConnectionStat(packet: Packet) -> Result<UniConnectionStat, NetworkStatError> {
    let data = packet.data;

    // skip all the vlan tags
    let mut currentIndex = 12;

    loop {
        let tag = u16::from_be_bytes(
            data.get(currentIndex..currentIndex + 2)
                .ok_or(NetworkStatError::CONVERT_ERROR)?
                .try_into()
                .unwrap(),
        );
        match tag {
            0x0800 | 0x86DD => break,
            0x8100 | 0x88A8 => currentIndex += 4,
            vlanTag => return Err(NetworkStatError::UNKNOWN_VLAN_TAG(vlanTag)),
        }
    }

    let data = &data[currentIndex..];

    let result = match u16::from_be_bytes(
        data.get(0..2)
            .ok_or(NetworkStatError::CONVERT_ERROR)?
            .try_into()
            .unwrap(),
    ) {
        0x0800 => ParseIpv4Packet(&data[2..]),
        0x86DD => ParseIpv6Packet(&data[2..]),
        protocol => Err(NetworkStatError::UNKNOWN_PROTOCOL(protocol)),
    };

    result.and_then(|mut x| {
        x.totalDataCount = DataCount::FromByte(packet.header.len.try_into().unwrap());
        Ok(x)
    })
}

fn ControlThread(
    controlDataInReadEnd: Receiver<()>,
    controlDataOutWriteEnd: Sender<NetworkRawStat>,
) -> Result<(), NetworkStatError> {
    // get interface list
    let devices = Device::list()?;

    let mut threadDatas: HashMap<String, Arc<Mutex<ThreadData>>> = HashMap::new();

    loop {
        // check if someone want to get data
        match controlDataInReadEnd
            .recv_timeout(config::GetGlobalConfig()?.ControlCommandReceiveTimeout())
        {
            Ok(_) => {
                let mut networkRawStat = NetworkRawStat::New();

                // build inode lookup table
                let tcpContent = fs::read_to_string("/proc/net/tcp")?;
                let tcp6Content = fs::read_to_string("/proc/net/tcp6")?;
                let udpContent = fs::read_to_string("/proc/net/udp")?;
                let udp6Content = fs::read_to_string("/proc/net/udp6")?;

                let tcpLines: Vec<&str> = tcpContent.lines().collect();
                let tcp6Lines: Vec<&str> = tcp6Content.lines().collect();
                let udpLines: Vec<&str> = udpContent.lines().collect();
                let udp6Lines: Vec<&str> = udp6Content.lines().collect();

                for tcp in &tcpLines[1..] {
                    let a: Vec<&str> = tcp.split_whitespace().collect();
                    let b: Vec<&str> = a[1].split(':').collect();
                    let c: Vec<&str> = a[2].split(':').collect();

                    let d = common::ParseHexString(b[0], Endian::LITTLE)?;
                    let e = common::ParseHexString(b[1], Endian::BIG)?;
                    let f = common::ParseHexString(c[0], Endian::LITTLE)?;
                    let g = common::ParseHexString(c[1], Endian::BIG)?;

                    if d.len() != 4 || e.len() != 2 || f.len() != 4 || g.len() != 2 {
                        return Err(NetworkStatError::CONVERT_ERROR);
                    }

                    let localAddr = IpAddr::V4(Ipv4Addr::new(d[0], d[1], d[2], d[3]));
                    let localPort = u16::from_be_bytes(e[0..2].try_into().unwrap());

                    let remoteAddr = IpAddr::V4(Ipv4Addr::new(f[0], f[1], f[2], f[3]));
                    let remotePort = u16::from_be_bytes(g[0..2].try_into().unwrap());

                    if localAddr == nullIpv4 || remoteAddr == nullIpv4 {
                        continue;
                    }

                    let connection = Connection::New(
                        localAddr,
                        localPort,
                        remoteAddr,
                        remotePort,
                        ConnectionType::TCP,
                    );

                    networkRawStat
                        .connectionLookupTable
                        .insert(Inode::New(a[9].parse()?), connection);

                    'outer1: for device in &devices {
                        for address in &device.addresses {
                            if common::AddressInNetwork(
                                &localAddr,
                                &address.addr,
                                &address.netmask.unwrap(),
                            )
                            .unwrap_or(false)
                            {
                                networkRawStat
                                    .interfaceNameLookupTable
                                    .insert(connection, device.name.clone());
                                break 'outer1;
                            }
                        }
                    }
                }

                for tcp6 in &tcp6Lines[1..] {
                    let a: Vec<&str> = tcp6.split_whitespace().collect();
                    let b: Vec<&str> = a[1].split(':').collect();
                    let c: Vec<&str> = a[2].split(':').collect();

                    let d = common::ParseHexString(b[0], Endian::LITTLE)?;
                    let e = common::ParseHexString(b[1], Endian::BIG)?;
                    let f = common::ParseHexString(c[0], Endian::LITTLE)?;
                    let g = common::ParseHexString(c[1], Endian::BIG)?;

                    if d.len() != 16 || e.len() != 2 || f.len() != 16 || g.len() != 2 {
                        return Err(NetworkStatError::CONVERT_ERROR);
                    }

                    let x1 = u16::from_be_bytes(d[0..2].try_into().unwrap());
                    let x2 = u16::from_be_bytes(d[2..4].try_into().unwrap());
                    let x3 = u16::from_be_bytes(d[4..6].try_into().unwrap());
                    let x4 = u16::from_be_bytes(d[6..8].try_into().unwrap());
                    let x5 = u16::from_be_bytes(d[8..10].try_into().unwrap());
                    let x6 = u16::from_be_bytes(d[10..12].try_into().unwrap());
                    let x7 = u16::from_be_bytes(d[12..14].try_into().unwrap());
                    let x8 = u16::from_be_bytes(d[14..16].try_into().unwrap());
                    let localAddr = IpAddr::V6(Ipv6Addr::new(x1, x2, x3, x4, x5, x6, x7, x8));
                    let localPort = u16::from_be_bytes(e[0..2].try_into().unwrap());

                    let x1 = u16::from_be_bytes(f[0..2].try_into().unwrap());
                    let x2 = u16::from_be_bytes(f[2..4].try_into().unwrap());
                    let x3 = u16::from_be_bytes(f[4..6].try_into().unwrap());
                    let x4 = u16::from_be_bytes(f[6..8].try_into().unwrap());
                    let x5 = u16::from_be_bytes(f[8..10].try_into().unwrap());
                    let x6 = u16::from_be_bytes(f[10..12].try_into().unwrap());
                    let x7 = u16::from_be_bytes(f[12..14].try_into().unwrap());
                    let x8 = u16::from_be_bytes(f[14..16].try_into().unwrap());
                    let remoteAddr = IpAddr::V6(Ipv6Addr::new(x1, x2, x3, x4, x5, x6, x7, x8));
                    let remotePort = u16::from_be_bytes(g[0..2].try_into().unwrap());

                    let connection = Connection::New(
                        localAddr,
                        localPort,
                        remoteAddr,
                        remotePort,
                        ConnectionType::TCP,
                    );

                    if localAddr == nullIpv6 || remoteAddr == nullIpv6 {
                        continue;
                    }

                    networkRawStat
                        .connectionLookupTable
                        .insert(Inode::New(a[9].parse()?), connection);

                    'outer2: for device in &devices {
                        for address in &device.addresses {
                            if common::AddressInNetwork(
                                &localAddr,
                                &address.addr,
                                &address.netmask.unwrap(),
                            )
                            .unwrap_or(false)
                            {
                                networkRawStat
                                    .interfaceNameLookupTable
                                    .insert(connection, device.name.clone());
                                break 'outer2;
                            }
                        }
                    }
                }

                for udp in &udpLines[1..] {
                    let a: Vec<&str> = udp.split_whitespace().collect();
                    let b: Vec<&str> = a[1].split(':').collect();
                    let c: Vec<&str> = a[2].split(':').collect();

                    let d = common::ParseHexString(b[0], Endian::LITTLE)?;
                    let e = common::ParseHexString(b[1], Endian::BIG)?;
                    let f = common::ParseHexString(c[0], Endian::LITTLE)?;
                    let g = common::ParseHexString(c[1], Endian::BIG)?;

                    if d.len() != 4 || e.len() != 2 || f.len() != 4 || g.len() != 2 {
                        return Err(NetworkStatError::CONVERT_ERROR);
                    }

                    let localAddr = IpAddr::V4(Ipv4Addr::new(d[0], d[1], d[2], d[3]));
                    let localPort = u16::from_be_bytes(e[0..2].try_into().unwrap());

                    let remoteAddr = IpAddr::V4(Ipv4Addr::new(f[0], f[1], f[2], f[3]));
                    let remotePort = u16::from_be_bytes(g[0..2].try_into().unwrap());

                    let connection = Connection::New(
                        localAddr,
                        localPort,
                        remoteAddr,
                        remotePort,
                        ConnectionType::UDP,
                    );

                    if localAddr == nullIpv4 || remoteAddr == nullIpv4 {
                        continue;
                    }

                    networkRawStat
                        .connectionLookupTable
                        .insert(Inode::New(a[9].parse()?), connection);

                    'outer3: for device in &devices {
                        for address in &device.addresses {
                            if common::AddressInNetwork(
                                &localAddr,
                                &address.addr,
                                &address.netmask.unwrap(),
                            )
                            .unwrap_or(false)
                            {
                                networkRawStat
                                    .interfaceNameLookupTable
                                    .insert(connection, device.name.clone());
                                break 'outer3;
                            }
                        }
                    }
                }

                for udp6 in &udp6Lines[1..] {
                    let a: Vec<&str> = udp6.split_whitespace().collect();
                    let b: Vec<&str> = a[1].split(':').collect();
                    let c: Vec<&str> = a[2].split(':').collect();

                    let d = common::ParseHexString(b[0], Endian::LITTLE)?;
                    let e = common::ParseHexString(b[1], Endian::BIG)?;
                    let f = common::ParseHexString(c[0], Endian::LITTLE)?;
                    let g = common::ParseHexString(c[1], Endian::BIG)?;

                    if d.len() != 16 || e.len() != 2 || f.len() != 16 || g.len() != 2 {
                        return Err(NetworkStatError::CONVERT_ERROR);
                    }

                    let x1 = u16::from_be_bytes(d[0..2].try_into().unwrap());
                    let x2 = u16::from_be_bytes(d[2..4].try_into().unwrap());
                    let x3 = u16::from_be_bytes(d[4..6].try_into().unwrap());
                    let x4 = u16::from_be_bytes(d[6..8].try_into().unwrap());
                    let x5 = u16::from_be_bytes(d[8..10].try_into().unwrap());
                    let x6 = u16::from_be_bytes(d[10..12].try_into().unwrap());
                    let x7 = u16::from_be_bytes(d[12..14].try_into().unwrap());
                    let x8 = u16::from_be_bytes(d[14..16].try_into().unwrap());
                    let localAddr = IpAddr::V6(Ipv6Addr::new(x1, x2, x3, x4, x5, x6, x7, x8));
                    let localPort = u16::from_be_bytes(e[0..2].try_into().unwrap());

                    let x1 = u16::from_be_bytes(f[0..2].try_into().unwrap());
                    let x2 = u16::from_be_bytes(f[2..4].try_into().unwrap());
                    let x3 = u16::from_be_bytes(f[4..6].try_into().unwrap());
                    let x4 = u16::from_be_bytes(f[6..8].try_into().unwrap());
                    let x5 = u16::from_be_bytes(f[8..10].try_into().unwrap());
                    let x6 = u16::from_be_bytes(f[10..12].try_into().unwrap());
                    let x7 = u16::from_be_bytes(f[12..14].try_into().unwrap());
                    let x8 = u16::from_be_bytes(f[14..16].try_into().unwrap());
                    let remoteAddr = IpAddr::V6(Ipv6Addr::new(x1, x2, x3, x4, x5, x6, x7, x8));
                    let remotePort = u16::from_be_bytes(g[0..2].try_into().unwrap());

                    let connection = Connection::New(
                        localAddr,
                        localPort,
                        remoteAddr,
                        remotePort,
                        ConnectionType::UDP,
                    );

                    if localAddr == nullIpv6 || remoteAddr == nullIpv6 {
                        continue;
                    }

                    networkRawStat
                        .connectionLookupTable
                        .insert(Inode::New(a[9].parse()?), connection);

                    'outer4: for device in &devices {
                        for address in &device.addresses {
                            if common::AddressInNetwork(
                                &localAddr,
                                &address.addr,
                                &address.netmask.unwrap(),
                            )
                            .unwrap_or(false)
                            {
                                networkRawStat
                                    .interfaceNameLookupTable
                                    .insert(connection, device.name.clone());
                                break 'outer4;
                            }
                        }
                    }
                }

                // build interface raw stats
                for (interfaceName, threadData) in &threadDatas {
                    let mut mutexLock = threadData.lock()?;

                    let mut interfaceRawStat = InterfaceRawStat::New(
                        interfaceName.clone(),
                        mutexLock.device.desc.clone().unwrap_or(String::new()),
                    );

                    interfaceRawStat.uniConnectionStats = mutexLock
                        .uniConnectionStats
                        .take()
                        .unwrap_or(HashMap::new());

                    networkRawStat
                        .interfaceRawStats
                        .insert(interfaceName.clone(), interfaceRawStat);
                }

                // send networkRawStat out
                controlDataOutWriteEnd.send(networkRawStat)?;
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                return Err(NetworkStatError::CHANNEL_RECV_ERROR)
            }
        }

        // check and remove any dead thread
        threadDatas = threadDatas
            .into_iter()
            .filter(|(_, threadData)| Arc::strong_count(&threadData) == 2)
            .collect();

        for device in &devices {
            let interfaceName = device.name.clone();

            // spawn new monitor thread if interface is not in monitoring list
            if !threadDatas.contains_key(&interfaceName) {
                let threadData = Arc::new(Mutex::new(ThreadData {
                    device: device.clone(),
                    uniConnectionStats: None,
                }));

                threadDatas.insert(interfaceName, Arc::clone(&threadData));

                // pass the thread data
                thread::spawn(move || CaptureThread(threadData));
            }
        }
    }
}

fn CaptureThread(threadData: Arc<Mutex<ThreadData>>) -> Result<(), NetworkStatError> {
    // init capture
    let device = threadData.lock()?.device.clone();

    let mut capture = Capture::from_device(device)?
        .snaplen(
            config::GetGlobalConfig()?
                .CaptureSizeLimit()
                .try_into()
                .unwrap(),
        )
        .timeout(
            config::GetGlobalConfig()?
                .CaptureThreadReceiveTimeout()
                .as_millis()
                .try_into()
                .unwrap(),
        )
        .precision(Precision::Nano)
        .open()?;

    // main loop
    loop {
        // check if control thread want this thread to exit
        if Arc::strong_count(&threadData) == 1 {
            // exit now
            return Ok(());
        }

        match capture.next() {
            Ok(packet) => {
                let mut mutexLock = threadData.lock()?;

                if mutexLock.uniConnectionStats.is_none() {
                    mutexLock.uniConnectionStats = Some(HashMap::new());
                }

                let uniConnectionStat = match GetUniConnectionStat(packet) {
                    Ok(stat) => stat,
                    Err(_) => continue,
                };

                *mutexLock
                    .uniConnectionStats
                    .as_mut()
                    .unwrap()
                    .entry(uniConnectionStat.uniConnection)
                    .or_insert(uniConnectionStat) += uniConnectionStat;
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(pcapError) => return Err(NetworkStatError::PCAP_ERROR(pcapError)),
        }
    }
}

lazy_static! {
    static ref controlDataInWriteEnd: Mutex<Option<Sender<()>>> = Mutex::new(None);
    static ref controlDataOutReadEnd: Mutex<Option<Receiver<NetworkRawStat>>> = Mutex::new(None);
}

pub fn InitNetworkStatCapture() -> Result<(), NetworkStatError> {
    let (_controlDataInWriteEnd, controlDataInReadEnd) = mpsc::channel();
    let (controlDataOutWriteEnd, _controlDataOutReadEnd) = mpsc::channel();

    *controlDataInWriteEnd.lock()? = Some(_controlDataInWriteEnd);
    *controlDataOutReadEnd.lock()? = Some(_controlDataOutReadEnd);

    thread::spawn(move || ControlThread(controlDataInReadEnd, controlDataOutWriteEnd));

    Ok(())
}

pub fn GetNetworkRawStat() -> Result<NetworkRawStat, NetworkStatError> {
    // signal to control thread to get data
    controlDataInWriteEnd.lock()?.as_ref().unwrap().send(())?;

    // get data from control thread
    Ok(controlDataOutReadEnd.lock()?.as_ref().unwrap().recv()?)
}

#[derive(Debug)]
pub enum NetworkStatError {
    CONVERT_ERROR,
    CHANNEL_SEND_ERROR,
    CHANNEL_RECV_ERROR,
    PARSE_INT_ERROR(std::num::ParseIntError),
    PCAP_ERROR(pcap::Error),
    UNKNOWN_VLAN_TAG(u16),
    UNKNOWN_PROTOCOL(u16),
    IPV4_PACKET_LENGTH_ERROR(usize),
    IPV4_PACKET_VERSION_ERROR(u8),
    IPV6_PACKET_LENGTH_ERROR(usize),
    IPV6_PACKET_VERSION_ERROR(u8),
    IPV6_UNKNOWN_OPTIONAL_HEADER_TYPE(u8),
    POISON_MUTEX,
    UNSUPPORTED_PROTOCOL(u8),
    IO_ERROR(io::Error),
    COMMON_ERROR(CommonError),
    CONFIG_ERROR(ConfigError),
}

impl std::error::Error for NetworkStatError {}

impl fmt::Display for NetworkStatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let result = match self {
            Self::CONVERT_ERROR => String::from(format!("Convert error")),
            Self::CHANNEL_SEND_ERROR => String::from(format!("Channel send error")),
            Self::CHANNEL_RECV_ERROR => String::from(format!("Channel recv error")),
            Self::PARSE_INT_ERROR(error) => String::from(format!("Parse integer error: {}", error)),

            Self::PCAP_ERROR(error) => String::from(format!("Pcap error: {}", error)),
            Self::UNKNOWN_VLAN_TAG(vlanTag) => {
                String::from(format!("Unknown vlan tag: {}", vlanTag))
            }
            Self::UNKNOWN_PROTOCOL(protocol) => {
                String::from(format!("Unknown protocol: {}", protocol))
            }
            Self::IPV4_PACKET_LENGTH_ERROR(len) => {
                String::from(format!("Ipv4 packet length error: {}", len))
            }
            Self::IPV4_PACKET_VERSION_ERROR(version) => {
                String::from(format!("Ipv4 packet version error: {}", version))
            }
            Self::IPV6_PACKET_LENGTH_ERROR(len) => {
                String::from(format!("Ipv6 packet length error: {}", len))
            }
            Self::IPV6_PACKET_VERSION_ERROR(version) => {
                String::from(format!("Ipv6 packet version error: {}", version))
            }
            Self::IPV6_UNKNOWN_OPTIONAL_HEADER_TYPE(headerType) => String::from(format!(
                "Ipv6 unknown optional header error: {}",
                headerType
            )),
            Self::POISON_MUTEX => String::from(format!("Mutex poison error")),
            Self::UNSUPPORTED_PROTOCOL(protocol) => {
                String::from(format!("Unsupported protocol: {}", protocol))
            }
            Self::IO_ERROR(error) => String::from(format!("IO error: {}", error)),
            Self::COMMON_ERROR(error) => String::from(format!("Common error: {}", error)),
            Self::CONFIG_ERROR(configError) => {
                String::from(format!("Config error: {}", configError))
            }
        };

        write!(f, "{}", result)
    }
}

impl From<pcap::Error> for NetworkStatError {
    fn from(error: pcap::Error) -> Self {
        Self::PCAP_ERROR(error)
    }
}

impl From<std::num::ParseIntError> for NetworkStatError {
    fn from(error: std::num::ParseIntError) -> Self {
        Self::PARSE_INT_ERROR(error)
    }
}

impl<T> From<std::sync::PoisonError<T>> for NetworkStatError {
    fn from(_: std::sync::PoisonError<T>) -> Self {
        Self::POISON_MUTEX
    }
}

impl<T> From<mpsc::SendError<T>> for NetworkStatError {
    fn from(_: mpsc::SendError<T>) -> Self {
        Self::CHANNEL_SEND_ERROR
    }
}

impl From<mpsc::RecvError> for NetworkStatError {
    fn from(_: mpsc::RecvError) -> Self {
        Self::CHANNEL_RECV_ERROR
    }
}

impl From<io::Error> for NetworkStatError {
    fn from(error: io::Error) -> Self {
        Self::IO_ERROR(error)
    }
}

impl From<CommonError> for NetworkStatError {
    fn from(error: CommonError) -> Self {
        Self::COMMON_ERROR(error)
    }
}

impl From<ConfigError> for NetworkStatError {
    fn from(error: ConfigError) -> Self {
        Self::CONFIG_ERROR(error)
    }
}
