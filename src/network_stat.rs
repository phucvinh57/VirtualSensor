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

const NULL_IPV4: IpAddr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
const NULL_IPV6: IpAddr = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Serialize)]
pub enum ConnectionType {
    TCP,
    UDP,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Serialize)]
pub struct UniConnection {
    src_addr: IpAddr,
    src_port: u16,
    dest_addr: IpAddr,
    dest_port: u16,
    conn_type: ConnectionType,
}

impl UniConnection {
    pub fn new(
        src_addr: IpAddr,
        src_port: u16,
        dest_addr: IpAddr,
        dest_port: u16,
        conn_type: ConnectionType,
    ) -> Self {
        Self {
            src_addr,
            src_port,
            dest_addr,
            dest_port,
            conn_type,
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Serialize)]
pub struct Connection {
    local_addr: IpAddr,
    local_port: u16,
    remote_addr: IpAddr,
    remote_port: u16,
    conn_type: ConnectionType,
}

impl Connection {
    pub fn new(
        local_addr: IpAddr,
        local_port: u16,
        remote_addr: IpAddr,
        remote_port: u16,
        conn_type: ConnectionType,
    ) -> Self {
        Self {
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            conn_type,
        }
    }

    pub fn get_local_addr(&self) -> IpAddr {
        self.local_addr
    }

    pub fn get_local_port(&self) -> u16 {
        self.local_port
    }

    pub fn get_remote_addr(&self) -> IpAddr {
        self.remote_addr
    }

    pub fn get_remote_port(&self) -> u16 {
        self.remote_port
    }

    pub fn get_conn_type(&self) -> ConnectionType {
        self.conn_type
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Serialize)]
pub struct UniConnectionStat {
    uni_conn: UniConnection,

    packet_count: Count,
    total_data_count: DataCount,
    real_data_count: DataCount,

    #[serde(skip_serializing)]
    is_used: bool,
}

#[allow(unused)]
impl UniConnectionStat {
    pub fn new(uni_conn: UniConnection) -> Self {
        Self {
            uni_conn,

            packet_count: Count::new(0),
            total_data_count: DataCount::from_byte(0),
            real_data_count: DataCount::from_byte(0),

            is_used: false,
        }
    }

    pub fn get_uni_conn(&self) -> UniConnection {
        self.uni_conn
    }

    pub fn get_packet_count(&self) -> Count {
        self.packet_count
    }

    pub fn get_total_data_count(&self) -> DataCount {
        self.total_data_count
    }

    pub fn get_real_data_count(&self) -> DataCount {
        self.real_data_count
    }

    fn mark_as_used(&mut self) {
        self.is_used = true;
    }
}

impl Add<Self> for UniConnectionStat {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        assert!(
            self.uni_conn == other.uni_conn,
            "Can't add different uniconnections!"
        );

        Self {
            uni_conn: self.uni_conn,

            packet_count: self.packet_count + other.packet_count,
            total_data_count: self.total_data_count + other.total_data_count,
            real_data_count: self.real_data_count + other.real_data_count,

            is_used: false,
        }
    }
}

impl AddAssign<Self> for UniConnectionStat {
    fn add_assign(&mut self, other: Self) {
        assert!(
            self.uni_conn == other.uni_conn,
            "Can't add different uniconnections!"
        );

        self.packet_count += other.packet_count;
        self.total_data_count += other.total_data_count;
        self.real_data_count += other.real_data_count;
    }
}

#[derive(Debug)]
struct ThreadData {
    device: Device,
    uni_conn_stats: Option<HashMap<UniConnection, UniConnectionStat>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InterfaceRawStat {
    iname: String,
    description: String,

    #[serde(serialize_with = "get_irawstat_uni_conn_stats_serialize")]
    uni_conn_stats: HashMap<UniConnection, UniConnectionStat>,
}

impl InterfaceRawStat {
    pub fn new(iname: String, description: String) -> Self {
        Self {
            iname,
            description,
            uni_conn_stats: HashMap::new(),
        }
    }

    pub fn get_uni_conn_stat(
        &mut self,
        uni_conn: &UniConnection,
    ) -> Option<&UniConnectionStat> {
        self.uni_conn_stats.get_mut(uni_conn).map(|x| {
            x.mark_as_used();
            &*x
        })
    }

    pub fn remove_used_uni_conn_stats(&mut self) {
        self.uni_conn_stats
            .retain(|_uni_conn, uni_conn_stat| !uni_conn_stat.is_used);
    }
}

fn get_irawstat_uni_conn_stats_serialize<S: Serializer>(
    input: &HashMap<UniConnection, UniConnectionStat>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(input.values())
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkRawStat {
    #[serde(skip_serializing)]
    conn_lookup_table: HashMap<Inode, Connection>,

    #[serde(skip_serializing)]
    iname_lookup_table: HashMap<Connection, String>,

    #[serde(serialize_with = "get_network_rawstat_uni_connection_stats_serialize")]
    irawstats: HashMap<String, InterfaceRawStat>,
}

impl NetworkRawStat {
    pub fn new() -> Self {
        Self {
            conn_lookup_table: HashMap::new(),
            iname_lookup_table: HashMap::new(),
            irawstats: HashMap::new(),
        }
    }

    pub fn lookup_connection(&self, inode: &Inode) -> Option<&Connection> {
        self.conn_lookup_table
            .get(inode)
            .and_then(|connection| Some(connection))
    }

    pub fn lookup_interface_name(&self, connection: &Connection) -> Option<&str> {
        self.iname_lookup_table
            .get(connection)
            .and_then(|name| Some(name.as_str()))
    }

    pub fn get_irawstat(&mut self, iname: &str) -> Option<&mut InterfaceRawStat> {
        self.irawstats
            .get_mut(iname)
            .and_then(|irawstat| Some(irawstat))
    }

    pub fn remove_unused_uni_connection_stats(&mut self) {
        for (_, irawstat) in &mut self.irawstats {
            irawstat.remove_used_uni_conn_stats();
        }
    }
}

fn get_network_rawstat_uni_connection_stats_serialize<S: Serializer>(
    input: &HashMap<String, InterfaceRawStat>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(input.values())
}

fn parse_ipv4_packet(data: &[u8]) -> Result<UniConnectionStat, NetworkStatError> {
    const IPV4_FIXED_HEADER_SIZE: usize = 20;

    // check fixed header len
    if data.len() < IPV4_FIXED_HEADER_SIZE {
        return Err(NetworkStatError::Ipv4PacketLenErr(data.len()));
    }

    // check version
    if data[0] & 0xf0 != 0x40
    // not ipv4
    {
        return Err(NetworkStatError::Ipv4PacketVersionErr(data[0] & 0xf0));
    }

    // get header len
    let header_len = ((data[0] & 0x0f) * 4) as usize;

    // get payload len
    let payload_length = u16::from_be_bytes(data[2..4].try_into().unwrap()) as usize - header_len;

    // get payload protocol
    let conn_type = match data[9] {
        TCP_PAYLOAD_TYPE => ConnectionType::TCP,
        UDP_PAYLOAD_TYPE => ConnectionType::UDP,
        _ => return Err(NetworkStatError::UnsupportedProtocol(data[9])),
    };

    // get src ip begin at data[12]
    let src_addr = IpAddr::V4(Ipv4Addr::new(data[12], data[13], data[14], data[15]));

    // get des ip begin at data[16]
    let dest_addr = IpAddr::V4(Ipv4Addr::new(data[16], data[17], data[18], data[19]));

    // get source port
    let src_port = u16::from_be_bytes(
        data.get(header_len..header_len + 2)
            .ok_or(NetworkStatError::ConvertErr)?
            .try_into()
            .unwrap(),
    );

    // get des port
    let dest_port = u16::from_be_bytes(
        data.get(header_len + 2..header_len + 4)
            .ok_or(NetworkStatError::ConvertErr)?
            .try_into()
            .unwrap(),
    );

    Ok(UniConnectionStat {
        uni_conn: UniConnection::new(src_addr, src_port, dest_addr, dest_port, conn_type),

        packet_count: Count::new(1),
        total_data_count: DataCount::from_byte(0),
        real_data_count: DataCount::from_byte(payload_length),

        is_used: false,
    })
}

fn parse_ipv6_packet(data: &[u8]) -> Result<UniConnectionStat, NetworkStatError> {
    const IPV6_FIXED_HEADER_SIZE: usize = 40;

    // check fixed header len
    if data.len() < IPV6_FIXED_HEADER_SIZE {
        return Err(NetworkStatError::Ipv6PacketLenErr(data.len()));
    }

    // check version
    if data[0] & 0xf0 != 0x60
    // not ipv6
    {
        return Err(NetworkStatError::Ipv6PacketVersionErr(data[0] & 0xf0));
    }

    // get payload length
    let payload_length = u16::from_be_bytes(data[4..6].try_into().unwrap()) as usize;

    // get src ip begin at data[8]
    let a = u16::from_be_bytes(data[8..10].try_into().unwrap());
    let b = u16::from_be_bytes(data[10..12].try_into().unwrap());
    let c = u16::from_be_bytes(data[12..14].try_into().unwrap());
    let d = u16::from_be_bytes(data[14..16].try_into().unwrap());
    let e = u16::from_be_bytes(data[16..18].try_into().unwrap());
    let f = u16::from_be_bytes(data[18..20].try_into().unwrap());
    let g = u16::from_be_bytes(data[20..22].try_into().unwrap());
    let h = u16::from_be_bytes(data[22..24].try_into().unwrap());
    let src_addr = IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h));

    // get des ip begin at data[24]
    let a = u16::from_be_bytes(data[24..26].try_into().unwrap());
    let b = u16::from_be_bytes(data[26..28].try_into().unwrap());
    let c = u16::from_be_bytes(data[28..30].try_into().unwrap());
    let d = u16::from_be_bytes(data[30..32].try_into().unwrap());
    let e = u16::from_be_bytes(data[32..34].try_into().unwrap());
    let f = u16::from_be_bytes(data[34..36].try_into().unwrap());
    let g = u16::from_be_bytes(data[36..38].try_into().unwrap());
    let h = u16::from_be_bytes(data[38..40].try_into().unwrap());
    let dest_addr = IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h));

    // skip through ipv6 extension headers
    let mut next_header_type = data[6];
    let mut curr_idx = IPV6_FIXED_HEADER_SIZE;
    let ipv6_extension_header_types = [0, 43, 44, 51, 50, 60, 135, 139, 140, 253, 254];
    let normal_payload_types = [6, 17];

    loop {
        match next_header_type {
            x if normal_payload_types.contains(&x) => break,
            x if ipv6_extension_header_types.contains(&x) => {
                let tmp = data
                    .get(curr_idx..curr_idx + 2)
                    .ok_or(NetworkStatError::ConvertErr)?;
                next_header_type = tmp[0];
                curr_idx += tmp[1] as usize;
            }
            header_type => return Err(NetworkStatError::Ipv6UnknownOptionalHeaderType(header_type)),
        }
    }

    // get payload protocol
    let conn_type = match next_header_type {
        TCP_PAYLOAD_TYPE => ConnectionType::TCP,
        UDP_PAYLOAD_TYPE => ConnectionType::UDP,
        _ => return Err(NetworkStatError::UnsupportedProtocol(next_header_type)),
    };

    // get src port
    let src_port = u16::from_be_bytes(
        data.get(curr_idx..curr_idx + 2)
            .ok_or(NetworkStatError::ConvertErr)?
            .try_into()
            .unwrap(),
    );

    // get des port
    let dest_port = u16::from_be_bytes(
        data.get(curr_idx + 2..curr_idx + 4)
            .ok_or(NetworkStatError::ConvertErr)?
            .try_into()
            .unwrap(),
    );

    Ok(UniConnectionStat {
        uni_conn: UniConnection::new(src_addr, src_port, dest_addr, dest_port, conn_type),

        packet_count: Count::new(1),
        total_data_count: DataCount::from_byte(0),
        real_data_count: DataCount::from_byte(
            payload_length - (curr_idx - IPV6_FIXED_HEADER_SIZE),
        ),

        is_used: false,
    })
}

fn get_uni_conn_stat(packet: Packet) -> Result<UniConnectionStat, NetworkStatError> {
    let data = packet.data;

    // skip all the vlan tags
    let mut curr_idx = 12;

    loop {
        let tag = u16::from_be_bytes(
            data.get(curr_idx..curr_idx + 2)
                .ok_or(NetworkStatError::ConvertErr)?
                .try_into()
                .unwrap(),
        );
        match tag {
            0x0800 | 0x86DD => break,
            0x8100 | 0x88A8 => curr_idx += 4,
            vlan_tag => return Err(NetworkStatError::UnknownVLANTag(vlan_tag)),
        }
    }

    let data = &data[curr_idx..];

    let result = match u16::from_be_bytes(
        data.get(0..2)
            .ok_or(NetworkStatError::ConvertErr)?
            .try_into()
            .unwrap(),
    ) {
        0x0800 => parse_ipv4_packet(&data[2..]),
        0x86DD => parse_ipv6_packet(&data[2..]),
        protocol => Err(NetworkStatError::UnknownProtocol(protocol)),
    };

    result.and_then(|mut x| {
        x.total_data_count = DataCount::from_byte(packet.header.len.try_into().unwrap());
        Ok(x)
    })
}

fn control_thread(
    ctrl_data_in_read_end: Receiver<()>,
    ctrl_data_in_write_end: Sender<NetworkRawStat>,
) -> Result<(), NetworkStatError> {
    // get interface list
    let devices = Device::list()?;

    let mut thread_data: HashMap<String, Arc<Mutex<ThreadData>>> = HashMap::new();

    loop {
        // check if someone want to get data
        match ctrl_data_in_read_end
            .recv_timeout(config::get_glob_conf()?.get_control_command_receive_timeout())
        {
            Ok(_) => {
                let mut network_raw_stat = NetworkRawStat::new();

                // build inode lookup table
                let tcp_content = fs::read_to_string("/proc/net/tcp")?;
                let tcp6_content = fs::read_to_string("/proc/net/tcp6")?;
                let udp_content = fs::read_to_string("/proc/net/udp")?;
                let udp6_content = fs::read_to_string("/proc/net/udp6")?;

                let tcp_lines: Vec<&str> = tcp_content.lines().collect();
                let tcp6_lines: Vec<&str> = tcp6_content.lines().collect();
                let udp_lines: Vec<&str> = udp_content.lines().collect();
                let udp6_lines: Vec<&str> = udp6_content.lines().collect();

                for tcp in &tcp_lines[1..] {
                    let a: Vec<&str> = tcp.split_whitespace().collect();
                    let b: Vec<&str> = a[1].split(':').collect();
                    let c: Vec<&str> = a[2].split(':').collect();

                    let d = common::parse_hex_str(b[0], Endian::Little)?;
                    let e = common::parse_hex_str(b[1], Endian::Big)?;
                    let f = common::parse_hex_str(c[0], Endian::Little)?;
                    let g = common::parse_hex_str(c[1], Endian::Big)?;

                    if d.len() != 4 || e.len() != 2 || f.len() != 4 || g.len() != 2 {
                        return Err(NetworkStatError::ConvertErr);
                    }

                    let local_addr = IpAddr::V4(Ipv4Addr::new(d[0], d[1], d[2], d[3]));
                    let local_port = u16::from_be_bytes(e[0..2].try_into().unwrap());

                    let remote_addr = IpAddr::V4(Ipv4Addr::new(f[0], f[1], f[2], f[3]));
                    let remote_port = u16::from_be_bytes(g[0..2].try_into().unwrap());

                    if local_addr == NULL_IPV4 || remote_addr == NULL_IPV4 {
                        continue;
                    }

                    let connection = Connection::new(
                        local_addr,
                        local_port,
                        remote_addr,
                        remote_port,
                        ConnectionType::TCP,
                    );

                    network_raw_stat
                        .conn_lookup_table
                        .insert(Inode::new(a[9].parse()?), connection);

                    'outer1: for device in &devices {
                        for address in &device.addresses {
                            if common::addr_in_network(
                                &local_addr,
                                &address.addr,
                                &address.netmask.unwrap(),
                            )
                            .unwrap_or(false)
                            {
                                network_raw_stat
                                    .iname_lookup_table
                                    .insert(connection, device.name.clone());
                                break 'outer1;
                            }
                        }
                    }
                }

                for tcp6 in &tcp6_lines[1..] {
                    let a: Vec<&str> = tcp6.split_whitespace().collect();
                    let b: Vec<&str> = a[1].split(':').collect();
                    let c: Vec<&str> = a[2].split(':').collect();

                    let d = common::parse_hex_str(b[0], Endian::Little)?;
                    let e = common::parse_hex_str(b[1], Endian::Big)?;
                    let f = common::parse_hex_str(c[0], Endian::Little)?;
                    let g = common::parse_hex_str(c[1], Endian::Big)?;

                    if d.len() != 16 || e.len() != 2 || f.len() != 16 || g.len() != 2 {
                        return Err(NetworkStatError::ConvertErr);
                    }

                    let x1 = u16::from_be_bytes(d[0..2].try_into().unwrap());
                    let x2 = u16::from_be_bytes(d[2..4].try_into().unwrap());
                    let x3 = u16::from_be_bytes(d[4..6].try_into().unwrap());
                    let x4 = u16::from_be_bytes(d[6..8].try_into().unwrap());
                    let x5 = u16::from_be_bytes(d[8..10].try_into().unwrap());
                    let x6 = u16::from_be_bytes(d[10..12].try_into().unwrap());
                    let x7 = u16::from_be_bytes(d[12..14].try_into().unwrap());
                    let x8 = u16::from_be_bytes(d[14..16].try_into().unwrap());
                    let local_addr = IpAddr::V6(Ipv6Addr::new(x1, x2, x3, x4, x5, x6, x7, x8));
                    let local_port = u16::from_be_bytes(e[0..2].try_into().unwrap());

                    let x1 = u16::from_be_bytes(f[0..2].try_into().unwrap());
                    let x2 = u16::from_be_bytes(f[2..4].try_into().unwrap());
                    let x3 = u16::from_be_bytes(f[4..6].try_into().unwrap());
                    let x4 = u16::from_be_bytes(f[6..8].try_into().unwrap());
                    let x5 = u16::from_be_bytes(f[8..10].try_into().unwrap());
                    let x6 = u16::from_be_bytes(f[10..12].try_into().unwrap());
                    let x7 = u16::from_be_bytes(f[12..14].try_into().unwrap());
                    let x8 = u16::from_be_bytes(f[14..16].try_into().unwrap());
                    let remote_addr = IpAddr::V6(Ipv6Addr::new(x1, x2, x3, x4, x5, x6, x7, x8));
                    let remote_port = u16::from_be_bytes(g[0..2].try_into().unwrap());

                    let connection = Connection::new(
                        local_addr,
                        local_port,
                        remote_addr,
                        remote_port,
                        ConnectionType::TCP,
                    );

                    if local_addr == NULL_IPV6 || remote_addr == NULL_IPV6 {
                        continue;
                    }

                    network_raw_stat
                        .conn_lookup_table
                        .insert(Inode::new(a[9].parse()?), connection);

                    'outer2: for device in &devices {
                        for address in &device.addresses {
                            if common::addr_in_network(
                                &local_addr,
                                &address.addr,
                                &address.netmask.unwrap(),
                            )
                            .unwrap_or(false)
                            {
                                network_raw_stat
                                    .iname_lookup_table
                                    .insert(connection, device.name.clone());
                                break 'outer2;
                            }
                        }
                    }
                }

                for udp in &udp_lines[1..] {
                    let a: Vec<&str> = udp.split_whitespace().collect();
                    let b: Vec<&str> = a[1].split(':').collect();
                    let c: Vec<&str> = a[2].split(':').collect();

                    let d = common::parse_hex_str(b[0], Endian::Little)?;
                    let e = common::parse_hex_str(b[1], Endian::Big)?;
                    let f = common::parse_hex_str(c[0], Endian::Little)?;
                    let g = common::parse_hex_str(c[1], Endian::Big)?;

                    if d.len() != 4 || e.len() != 2 || f.len() != 4 || g.len() != 2 {
                        return Err(NetworkStatError::ConvertErr);
                    }

                    let local_addr = IpAddr::V4(Ipv4Addr::new(d[0], d[1], d[2], d[3]));
                    let local_port = u16::from_be_bytes(e[0..2].try_into().unwrap());

                    let remote_addr = IpAddr::V4(Ipv4Addr::new(f[0], f[1], f[2], f[3]));
                    let remote_port = u16::from_be_bytes(g[0..2].try_into().unwrap());

                    let connection = Connection::new(
                        local_addr,
                        local_port,
                        remote_addr,
                        remote_port,
                        ConnectionType::UDP,
                    );

                    if local_addr == NULL_IPV4 || remote_addr == NULL_IPV4 {
                        continue;
                    }

                    network_raw_stat
                        .conn_lookup_table
                        .insert(Inode::new(a[9].parse()?), connection);

                    'outer3: for device in &devices {
                        for address in &device.addresses {
                            if common::addr_in_network(
                                &local_addr,
                                &address.addr,
                                &address.netmask.unwrap(),
                            )
                            .unwrap_or(false)
                            {
                                network_raw_stat
                                    .iname_lookup_table
                                    .insert(connection, device.name.clone());
                                break 'outer3;
                            }
                        }
                    }
                }

                for udp6 in &udp6_lines[1..] {
                    let a: Vec<&str> = udp6.split_whitespace().collect();
                    let b: Vec<&str> = a[1].split(':').collect();
                    let c: Vec<&str> = a[2].split(':').collect();

                    let d = common::parse_hex_str(b[0], Endian::Little)?;
                    let e = common::parse_hex_str(b[1], Endian::Big)?;
                    let f = common::parse_hex_str(c[0], Endian::Little)?;
                    let g = common::parse_hex_str(c[1], Endian::Big)?;

                    if d.len() != 16 || e.len() != 2 || f.len() != 16 || g.len() != 2 {
                        return Err(NetworkStatError::ConvertErr);
                    }

                    let x1 = u16::from_be_bytes(d[0..2].try_into().unwrap());
                    let x2 = u16::from_be_bytes(d[2..4].try_into().unwrap());
                    let x3 = u16::from_be_bytes(d[4..6].try_into().unwrap());
                    let x4 = u16::from_be_bytes(d[6..8].try_into().unwrap());
                    let x5 = u16::from_be_bytes(d[8..10].try_into().unwrap());
                    let x6 = u16::from_be_bytes(d[10..12].try_into().unwrap());
                    let x7 = u16::from_be_bytes(d[12..14].try_into().unwrap());
                    let x8 = u16::from_be_bytes(d[14..16].try_into().unwrap());
                    let local_addr = IpAddr::V6(Ipv6Addr::new(x1, x2, x3, x4, x5, x6, x7, x8));
                    let local_port = u16::from_be_bytes(e[0..2].try_into().unwrap());

                    let x1 = u16::from_be_bytes(f[0..2].try_into().unwrap());
                    let x2 = u16::from_be_bytes(f[2..4].try_into().unwrap());
                    let x3 = u16::from_be_bytes(f[4..6].try_into().unwrap());
                    let x4 = u16::from_be_bytes(f[6..8].try_into().unwrap());
                    let x5 = u16::from_be_bytes(f[8..10].try_into().unwrap());
                    let x6 = u16::from_be_bytes(f[10..12].try_into().unwrap());
                    let x7 = u16::from_be_bytes(f[12..14].try_into().unwrap());
                    let x8 = u16::from_be_bytes(f[14..16].try_into().unwrap());
                    let remote_addr = IpAddr::V6(Ipv6Addr::new(x1, x2, x3, x4, x5, x6, x7, x8));
                    let remote_port = u16::from_be_bytes(g[0..2].try_into().unwrap());

                    let connection = Connection::new(
                        local_addr,
                        local_port,
                        remote_addr,
                        remote_port,
                        ConnectionType::UDP,
                    );

                    if local_addr == NULL_IPV6 || remote_addr == NULL_IPV6 {
                        continue;
                    }

                    network_raw_stat
                        .conn_lookup_table
                        .insert(Inode::new(a[9].parse()?), connection);

                    'outer4: for device in &devices {
                        for address in &device.addresses {
                            if common::addr_in_network(
                                &local_addr,
                                &address.addr,
                                &address.netmask.unwrap(),
                            )
                            .unwrap_or(false)
                            {
                                network_raw_stat
                                    .iname_lookup_table
                                    .insert(connection, device.name.clone());
                                break 'outer4;
                            }
                        }
                    }
                }

                // build interface raw stats
                for (iname, thread_data) in &thread_data {
                    let mut mutex_lock = thread_data.lock()?;

                    let mut irawstat = InterfaceRawStat::new(
                        iname.clone(),
                        mutex_lock.device.desc.clone().unwrap_or(String::new()),
                    );

                    irawstat.uni_conn_stats = mutex_lock
                        .uni_conn_stats
                        .take()
                        .unwrap_or(HashMap::new());

                    network_raw_stat
                        .irawstats
                        .insert(iname.clone(), irawstat);
                }

                // send networkRawStat out
                ctrl_data_in_write_end.send(network_raw_stat)?;
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return Err(NetworkStatError::ChannelRecvErr),
        }

        // check and remove any dead thread
        thread_data = thread_data
            .into_iter()
            .filter(|(_, thread_data)| Arc::strong_count(&thread_data) == 2)
            .collect();

        for device in &devices {
            let iname = device.name.clone();

            // spawn new monitor thread if interface is not in monitoring list
            if !thread_data.contains_key(&iname) {
                let _thread_data = Arc::new(Mutex::new(ThreadData {
                    device: device.clone(),
                    uni_conn_stats: None,
                }));

                thread_data.insert(iname, Arc::clone(&_thread_data));

                // pass the thread data
                thread::spawn(move || capture_thread(_thread_data));
            }
        }
    }
}

fn capture_thread(thread_data: Arc<Mutex<ThreadData>>) -> Result<(), NetworkStatError> {
    // init capture
    let device = thread_data.lock()?.device.clone();

    let mut capture = Capture::from_device(device)?
        .snaplen(
            config::get_glob_conf()?
                .get_capture_size_limit()
                .try_into()
                .unwrap(),
        )
        .timeout(
            config::get_glob_conf()?
                .get_capture_thread_receive_timeout()
                .as_millis()
                .try_into()
                .unwrap(),
        )
        .precision(Precision::Nano)
        .open()?;

    // main loop
    loop {
        // check if control thread want this thread to exit
        if Arc::strong_count(&thread_data) == 1 {
            // exit now
            return Ok(());
        }

        match capture.next() {
            Ok(packet) => {
                let mut mutex_lock = thread_data.lock()?;

                if mutex_lock.uni_conn_stats.is_none() {
                    mutex_lock.uni_conn_stats = Some(HashMap::new());
                }

                let uni_conn_stat = match get_uni_conn_stat(packet) {
                    Ok(stat) => stat,
                    Err(_) => continue,
                };

                *mutex_lock
                    .uni_conn_stats
                    .as_mut()
                    .unwrap()
                    .entry(uni_conn_stat.uni_conn)
                    .or_insert(uni_conn_stat) += uni_conn_stat;
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(pcap_err) => return Err(NetworkStatError::PcapErr(pcap_err)),
        }
    }
}

lazy_static! {
    static ref CONTROL_DATA_IN_WRITE_END: Mutex<Option<Sender<()>>> = Mutex::new(None);
    static ref CONTROL_DATA_IN_READ_END: Mutex<Option<Receiver<NetworkRawStat>>> = Mutex::new(None);
}

pub fn init_network_stat_capture() -> Result<(), NetworkStatError> {
    let (_control_data_in_write_end, control_data_in_read_end) = mpsc::channel();
    let (control_data_out_write_end, _control_data_out_read_end) = mpsc::channel();

    *CONTROL_DATA_IN_WRITE_END.lock()? = Some(_control_data_in_write_end);
    *CONTROL_DATA_IN_READ_END.lock()? = Some(_control_data_out_read_end);

    thread::spawn(move || control_thread(control_data_in_read_end, control_data_out_write_end));

    Ok(())
}

pub fn get_network_rawstat() -> Result<NetworkRawStat, NetworkStatError> {
    // signal to control thread to get data
    CONTROL_DATA_IN_WRITE_END
        .lock()?
        .as_ref()
        .unwrap()
        .send(())?;

    // get data from control thread
    Ok(CONTROL_DATA_IN_READ_END.lock()?.as_ref().unwrap().recv()?)
}

#[derive(Debug)]
pub enum NetworkStatError {
    ConvertErr,
    ChannelSendErr,
    ChannelRecvErr,
    ParseIntErr(std::num::ParseIntError),
    PcapErr(pcap::Error),
    UnknownVLANTag(u16),
    UnknownProtocol(u16),
    Ipv4PacketLenErr(usize),
    Ipv4PacketVersionErr(u8),
    Ipv6PacketLenErr(usize),
    Ipv6PacketVersionErr(u8),
    Ipv6UnknownOptionalHeaderType(u8),
    PoisonMutex,
    UnsupportedProtocol(u8),
    IOErr(io::Error),
    CommonErr(CommonError),
    ConfigErr(ConfigError),
}

impl std::error::Error for NetworkStatError {}

impl fmt::Display for NetworkStatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let result = match self {
            Self::ConvertErr => String::from(format!("Convert error")),
            Self::ChannelSendErr => String::from(format!("Channel send error")),
            Self::ChannelRecvErr => String::from(format!("Channel recv error")),
            Self::ParseIntErr(error) => String::from(format!("Parse integer error: {}", error)),

            Self::PcapErr(error) => String::from(format!("Pcap error: {}", error)),
            Self::UnknownVLANTag(vlan_tag) => String::from(format!("Unknown vlan tag: {}", vlan_tag)),
            Self::UnknownProtocol(protocol) => {
                String::from(format!("Unknown protocol: {}", protocol))
            }
            Self::Ipv4PacketLenErr(len) => {
                String::from(format!("Ipv4 packet length error: {}", len))
            }
            Self::Ipv4PacketVersionErr(version) => {
                String::from(format!("Ipv4 packet version error: {}", version))
            }
            Self::Ipv6PacketLenErr(len) => {
                String::from(format!("Ipv6 packet length error: {}", len))
            }
            Self::Ipv6PacketVersionErr(version) => {
                String::from(format!("Ipv6 packet version error: {}", version))
            }
            Self::Ipv6UnknownOptionalHeaderType(header_type) => String::from(format!(
                "Ipv6 unknown optional header error: {}",
                header_type
            )),
            Self::PoisonMutex => String::from(format!("Mutex poison error")),
            Self::UnsupportedProtocol(protocol) => {
                String::from(format!("Unsupported protocol: {}", protocol))
            }
            Self::IOErr(error) => String::from(format!("IO error: {}", error)),
            Self::CommonErr(error) => String::from(format!("Common error: {}", error)),
            Self::ConfigErr(config_err) => String::from(format!("Config error: {}", config_err)),
        };

        write!(f, "{}", result)
    }
}

impl From<pcap::Error> for NetworkStatError {
    fn from(error: pcap::Error) -> Self {
        Self::PcapErr(error)
    }
}

impl From<std::num::ParseIntError> for NetworkStatError {
    fn from(error: std::num::ParseIntError) -> Self {
        Self::ParseIntErr(error)
    }
}

impl<T> From<std::sync::PoisonError<T>> for NetworkStatError {
    fn from(_: std::sync::PoisonError<T>) -> Self {
        Self::PoisonMutex
    }
}

impl<T> From<mpsc::SendError<T>> for NetworkStatError {
    fn from(_: mpsc::SendError<T>) -> Self {
        Self::ChannelSendErr
    }
}

impl From<mpsc::RecvError> for NetworkStatError {
    fn from(_: mpsc::RecvError) -> Self {
        Self::ChannelRecvErr
    }
}

impl From<io::Error> for NetworkStatError {
    fn from(error: io::Error) -> Self {
        Self::IOErr(error)
    }
}

impl From<CommonError> for NetworkStatError {
    fn from(error: CommonError) -> Self {
        Self::CommonErr(error)
    }
}

impl From<ConfigError> for NetworkStatError {
    fn from(error: ConfigError) -> Self {
        Self::ConfigErr(error)
    }
}
