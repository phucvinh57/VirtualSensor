use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::ops::{Add, AddAssign};
use std::{fmt, fs, io};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::common::{CommonError, Count, DataCount, Gid, Inode, TimeCount, Timestamp, Uid};
use crate::config;
use crate::taskstat::{TaskStatsConnection, TaskStatsError};
use crate::network_stat::{Connection, NetworkRawStat, UniConnection, UniConnectionStat};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
pub struct Pid(u128);

impl Pid {
    pub fn new(pid: usize) -> Self {
        Self(pid.try_into().unwrap())
    }
    pub fn to_usize(&self) -> usize {
        self.0 as usize
    }
}

impl TryFrom<&str> for Pid {
    type Error = CommonError;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        Ok(Self(input.parse()?))
    }
}

impl Into<u32> for Pid {
    fn into(self) -> u32 {
        self.0 as u32
    }
}

impl fmt::Display for Pid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<'de> Deserialize<'de> for Pid {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Pid, D::Error> {
        Ok(Pid::new(Deserialize::deserialize(deserializer)?))
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
pub struct Tid(u128);

impl Tid {
    pub fn new(tid: usize) -> Self {
        Self(tid.try_into().unwrap())
    }
}

impl TryFrom<&str> for Tid {
    type Error = CommonError;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        Ok(Self(input.parse()?))
    }
}

impl Into<u32> for Tid {
    fn into(self) -> u32 {
        self.0 as u32
    }
}

impl fmt::Display for Tid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Serialize)]
pub struct ConnectionStat {
    connection: Connection,

    // packet count
    pack_sent: Count,
    pack_recv: Count,

    // data count in link layer
    total_data_sent: DataCount,
    total_data_recv: DataCount,

    // data count in higher level
    real_data_sent: DataCount,
    real_data_recv: DataCount,
}

impl ConnectionStat {
    pub fn new(connection: Connection) -> Self {
        Self {
            connection,

            pack_sent: Count::new(0),
            pack_recv: Count::new(0),

            total_data_sent: DataCount::from_byte(0),
            total_data_recv: DataCount::from_byte(0),

            real_data_sent: DataCount::from_byte(0),
            real_data_recv: DataCount::from_byte(0),
        }
    }

    pub fn get_connection(&self) -> Connection {
        self.connection
    }

    pub fn get_pack_sent(&self) -> Count {
        self.pack_sent
    }

    pub fn get_pack_recv(&self) -> Count {
        self.pack_recv
    }

    pub fn get_total_data_sent(&self) -> DataCount {
        self.total_data_sent
    }

    pub fn get_total_data_recv(&self) -> DataCount {
        self.total_data_recv
    }

    pub fn get_real_data_sent(&self) -> DataCount {
        self.real_data_sent
    }

    pub fn get_real_data_recv(&self) -> DataCount {
        self.real_data_recv
    }
}

impl Add<Self> for ConnectionStat {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        assert!(
            self.connection == other.connection,
            "Can't add different connections!"
        );

        Self {
            connection: self.connection,

            pack_sent: self.pack_sent + other.pack_sent,
            pack_recv: self.pack_recv + other.pack_recv,

            total_data_sent: self.total_data_sent + other.total_data_sent,
            total_data_recv: self.total_data_recv + other.total_data_recv,

            real_data_sent: self.real_data_sent + other.real_data_sent,
            real_data_recv: self.real_data_recv + other.real_data_recv,
        }
    }
}

impl AddAssign<Self> for ConnectionStat {
    fn add_assign(&mut self, other: Self) {
        assert!(
            self.connection == other.connection,
            "Can't add different connections!"
        );

        self.pack_sent += other.pack_sent;
        self.pack_recv += other.pack_recv;

        self.total_data_sent += other.total_data_sent;
        self.total_data_recv += other.total_data_recv;

        self.real_data_sent += other.real_data_sent;
        self.real_data_recv += other.real_data_recv;
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct InterfaceStat {
    iname: String,

    // packet count
    pack_sent: Count,
    packet_recv: Count,

    // data count in link layer
    total_data_sent: DataCount,
    total_data_recv: DataCount,

    // data count in higher level
    real_data_sent: DataCount,
    real_data_recv: DataCount,

    // map from Connection to ConnectionStat
    #[serde(serialize_with = "get_istat_conn_stats_serialize")]
    conn_stats: HashMap<Connection, ConnectionStat>,
}

#[allow(unused)]
impl InterfaceStat {
    pub fn new(iname: &str) -> Self {
        Self {
            iname: String::from(iname),

            pack_sent: Count::new(0),
            packet_recv: Count::new(0),

            total_data_sent: DataCount::from_byte(0),
            total_data_recv: DataCount::from_byte(0),

            real_data_sent: DataCount::from_byte(0),
            real_data_recv: DataCount::from_byte(0),

            conn_stats: HashMap::new(),
        }
    }

    pub fn get_interface_name(&self) -> String {
        self.iname.clone()
    }

    pub fn add_conn_stat(&mut self, conn_stat: ConnectionStat) {
        self.pack_sent += conn_stat.get_pack_sent();
        self.packet_recv += conn_stat.get_pack_recv();

        self.total_data_sent += conn_stat.get_total_data_sent();
        self.total_data_recv += conn_stat.get_total_data_recv();

        self.real_data_sent += conn_stat.get_real_data_sent();
        self.real_data_recv += conn_stat.get_real_data_recv();

        self.conn_stats
            .insert(conn_stat.get_connection(), conn_stat);
    }
}

impl Add<Self> for InterfaceStat {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        assert!(
            self.iname == other.iname,
            "Can't add different interface stats!"
        );

        let mut result = Self::new(&self.iname);

        result.pack_sent = self.pack_sent + other.pack_sent;
        result.packet_recv = self.packet_recv + other.packet_recv;

        result.total_data_sent = self.total_data_sent + other.total_data_sent;
        result.total_data_recv = self.total_data_recv + other.total_data_recv;

        result.real_data_sent = self.real_data_sent + other.real_data_sent;
        result.real_data_recv = self.real_data_recv + other.real_data_recv;

        // merge connectionStats
        result.conn_stats = self.conn_stats;

        for (other_conn, other_conn_stat) in other.conn_stats {
            if let Some(conn_stat) = result.conn_stats.get_mut(&other_conn) {
                *conn_stat += other_conn_stat;
            } else {
                result
                    .conn_stats
                    .insert(other_conn, other_conn_stat);
            }
        }

        result
    }
}

impl AddAssign<Self> for InterfaceStat {
    fn add_assign(&mut self, other: Self) {
        assert!(
            self.iname == other.iname,
            "Can't add different interface stats!"
        );

        self.pack_sent += other.pack_sent;
        self.packet_recv += other.packet_recv;

        self.total_data_sent += other.total_data_sent;
        self.total_data_recv += other.total_data_recv;

        self.real_data_sent += other.real_data_sent;
        self.real_data_recv += other.real_data_recv;

        // merge connectionStats
        for (other_conn, other_conn_stat) in other.conn_stats {
            if let Some(conn_stat) = self.conn_stats.get_mut(&other_conn) {
                *conn_stat += other_conn_stat;
            } else {
                self.conn_stats
                    .insert(other_conn, other_conn_stat);
            }
        }
    }
}

fn get_istat_conn_stats_serialize<S: Serializer>(
    input: &HashMap<Connection, ConnectionStat>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(input.values())
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkStat {
    // packet count
    pack_sent: Count,
    pack_recv: Count,

    // data count in link layer
    total_data_sent: DataCount,
    total_data_recv: DataCount,

    // data count in higher level
    real_data_sent: DataCount,
    real_data_recv: DataCount,

    // map from InterfaceName to InterfaceStat
    #[serde(serialize_with = "get_netstat_istats_serialize")]
    istats: HashMap<String, InterfaceStat>,
}

impl NetworkStat {
    pub fn new() -> Self {
        Self {
            pack_sent: Count::new(0),
            pack_recv: Count::new(0),

            total_data_sent: DataCount::from_byte(0),
            total_data_recv: DataCount::from_byte(0),

            real_data_sent: DataCount::from_byte(0),
            real_data_recv: DataCount::from_byte(0),

            istats: HashMap::new(),
        }
    }

    pub fn add_conn_stat(&mut self, iname: &str, conn_stat: ConnectionStat) {
        self.pack_sent += conn_stat.get_pack_sent();
        self.pack_recv += conn_stat.get_pack_recv();

        self.total_data_sent += conn_stat.get_total_data_sent();
        self.total_data_recv += conn_stat.get_total_data_recv();

        self.real_data_sent += conn_stat.get_real_data_sent();
        self.real_data_recv += conn_stat.get_real_data_recv();

        // create interface stat if not existed yet
        if !self.istats.contains_key(iname) {
            self.istats
                .insert(iname.to_string(), InterfaceStat::new(iname));
        }

        // insert the stat to interface stat
        self.istats
            .get_mut(iname)
            .unwrap()
            .add_conn_stat(conn_stat);
    }
}

impl Add<Self> for NetworkStat {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let mut result = Self::new();

        result.pack_sent = self.pack_sent + other.pack_sent;
        result.pack_recv = self.pack_recv + other.pack_recv;

        result.total_data_sent = self.total_data_sent + other.total_data_sent;
        result.total_data_recv = self.total_data_recv + other.total_data_recv;

        result.real_data_sent = self.real_data_sent + other.real_data_sent;
        result.real_data_recv = self.real_data_recv + other.real_data_recv;

        // merge interfaceStats
        result.istats = self.istats;

        for (other_iname, other_istat) in other.istats {
            if let Some(istat) = result.istats.get_mut(&other_iname) {
                *istat += other_istat;
            } else {
                result
                    .istats
                    .insert(other_iname, other_istat);
            }
        }

        result
    }
}

impl AddAssign<Self> for NetworkStat {
    fn add_assign(&mut self, other: Self) {
        self.pack_sent += other.pack_sent;
        self.pack_recv += other.pack_recv;

        self.total_data_sent += other.total_data_sent;
        self.total_data_recv += other.total_data_recv;

        self.real_data_sent += other.real_data_sent;
        self.real_data_recv += other.real_data_recv;

        // merge interfaceStats
        for (other_iname, other_istat) in other.istats {
            if let Some(istat) = self.istats.get_mut(&other_iname) {
                *istat += other_istat;
            } else {
                self.istats
                    .insert(other_iname, other_istat);
            }
        }
    }
}

fn get_netstat_istats_serialize<S: Serializer>(
    input: &HashMap<String, InterfaceStat>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(input.values())
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct ThreadStat {
    timestamp: Timestamp,

    total_system_cpu_time: TimeCount,
    total_user_cpu_time: TimeCount,
    total_cpu_time: TimeCount,

    total_io_read: DataCount,
    total_io_write: DataCount,

    total_block_io_read: DataCount,
    total_block_io_write: DataCount,
}

impl ThreadStat {
    pub fn new() -> Self {
        Self {
            timestamp: Timestamp::get_curr_timestamp(),

            total_system_cpu_time: TimeCount::from_secs(0),
            total_user_cpu_time: TimeCount::from_secs(0),
            total_cpu_time: TimeCount::from_secs(0),

            total_io_read: DataCount::from_byte(0),
            total_io_write: DataCount::from_byte(0),

            total_block_io_read: DataCount::from_byte(0),
            total_block_io_write: DataCount::from_byte(0),
        }
    }

    pub fn get_total_system_cpu_time(&self) -> TimeCount {
        self.total_system_cpu_time
    }
    pub fn get_total_user_cpu_time(&self) -> TimeCount {
        self.total_user_cpu_time
    }
    pub fn get_total_cpu_time(&self) -> TimeCount {
        self.total_cpu_time
    }

    pub fn get_total_io_read(&self) -> DataCount {
        self.total_io_read
    }
    pub fn get_total_io_write(&self) -> DataCount {
        self.total_io_write
    }

    pub fn get_total_block_io_read(&self) -> DataCount {
        self.total_block_io_read
    }
    pub fn get_total_block_io_write(&self) -> DataCount {
        self.total_block_io_write
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ProcessStat {
    timestamp: Timestamp,

    total_system_cpu_time: TimeCount,
    total_user_cpu_time: TimeCount,
    total_cpu_time: TimeCount,

    total_rss: DataCount,
    total_vss: DataCount,
    total_swap: DataCount,

    total_io_read: DataCount,
    total_io_write: DataCount,

    total_block_io_read: DataCount,
    total_block_io_write: DataCount,

    netstat: NetworkStat,
}

impl ProcessStat {
    pub fn new() -> Self {
        Self {
            timestamp: Timestamp::get_curr_timestamp(),

            total_system_cpu_time: TimeCount::from_secs(0),
            total_user_cpu_time: TimeCount::from_secs(0),
            total_cpu_time: TimeCount::from_secs(0),

            total_rss: DataCount::from_byte(0),
            total_vss: DataCount::from_byte(0),
            total_swap: DataCount::from_byte(0),

            total_io_read: DataCount::from_byte(0),
            total_io_write: DataCount::from_byte(0),

            total_block_io_read: DataCount::from_byte(0),
            total_block_io_write: DataCount::from_byte(0),

            netstat: NetworkStat::new(),
        }
    }
}

impl Add<Self> for ProcessStat {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self {
            timestamp: self.timestamp,

            total_system_cpu_time: self.total_system_cpu_time + other.total_system_cpu_time,
            total_user_cpu_time: self.total_user_cpu_time + other.total_user_cpu_time,
            total_cpu_time: self.total_cpu_time + other.total_cpu_time,

            total_rss: self.total_rss + other.total_rss,
            total_vss: self.total_vss + other.total_vss,
            total_swap: self.total_swap + other.total_swap,

            total_io_read: self.total_io_read + other.total_io_read,
            total_io_write: self.total_io_write + other.total_io_write,

            total_block_io_read: self.total_block_io_read + other.total_block_io_read,
            total_block_io_write: self.total_block_io_write + other.total_block_io_write,

            netstat: self.netstat + other.netstat,
        }
    }
}

impl Add<ThreadStat> for ProcessStat {
    type Output = Self;

    fn add(self, other: ThreadStat) -> Self {
        Self {
            timestamp: self.timestamp,

            total_system_cpu_time: self.total_system_cpu_time + other.get_total_system_cpu_time(),
            total_user_cpu_time: self.total_user_cpu_time + other.get_total_user_cpu_time(),
            total_cpu_time: self.total_cpu_time + other.get_total_cpu_time(),

            total_rss: self.total_rss,
            total_vss: self.total_vss,
            total_swap: self.total_swap,

            total_io_read: self.total_io_read + other.get_total_io_read(),
            total_io_write: self.total_io_write + other.get_total_io_write(),

            total_block_io_read: self.total_block_io_read + other.get_total_block_io_read(),
            total_block_io_write: self.total_block_io_write + other.get_total_block_io_write(),

            netstat: self.netstat,
        }
    }
}

impl AddAssign<Self> for ProcessStat {
    fn add_assign(&mut self, other: Self) {
        self.total_system_cpu_time += other.total_system_cpu_time;
        self.total_user_cpu_time += other.total_user_cpu_time;
        self.total_cpu_time += other.total_cpu_time;

        self.total_rss += other.total_rss;
        self.total_vss += other.total_vss;
        self.total_swap += other.total_swap;

        self.total_io_read += other.total_io_read;
        self.total_io_write += other.total_io_write;

        self.total_block_io_read += other.total_block_io_read;
        self.total_block_io_write += other.total_block_io_write;

        self.netstat += other.netstat;
    }
}

impl AddAssign<ThreadStat> for ProcessStat {
    fn add_assign(&mut self, other: ThreadStat) {
        self.total_system_cpu_time += other.get_total_system_cpu_time();
        self.total_user_cpu_time += other.get_total_user_cpu_time();
        self.total_cpu_time += other.get_total_cpu_time();

        self.total_io_read += other.get_total_io_read();
        self.total_io_write += other.get_total_io_write();

        self.total_block_io_read += other.get_total_block_io_read();
        self.total_block_io_write += other.get_total_block_io_write();
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Thread {
    // ids inside namespace
    tid: Tid,
    pid: Pid,

    // ids outside namespace
    real_tid: Tid,
    real_pid: Pid,

    // this thread stat
    stat: ThreadStat,
}

#[allow(unused)]
impl Thread {
    pub fn new(tid: Tid, pid: Pid, real_tid: Tid, real_pid: Pid) -> Self {
        Self {
            tid,
            pid,

            real_tid,
            real_pid,

            stat: ThreadStat::new(),
        }
    }

    pub fn get_tid(&self) -> Tid {
        self.tid
    }
    pub fn get_pid(&self) -> Pid {
        self.pid
    }

    pub fn get_real_tid(&self) -> Tid {
        self.real_tid
    }
    pub fn get_real_pid(&self) -> Pid {
        self.real_pid
    }

    // update this thread stat, and return a copy of it
    pub fn get_stat(
        &mut self,
        taskstats_conn: &mut TaskStatsConnection,
    ) -> Result<ThreadStat, ProcessError> {
        let thread_taskstats = taskstats_conn.get_thread_taskstats(self.real_tid)?;

        self.stat.total_system_cpu_time = thread_taskstats.systemCpuTime;
        self.stat.total_user_cpu_time = thread_taskstats.userCpuTime;
        self.stat.total_cpu_time = thread_taskstats.systemCpuTime + thread_taskstats.userCpuTime;

        self.stat.total_io_read = thread_taskstats.ioRead;
        self.stat.total_io_write = thread_taskstats.ioWrite;

        self.stat.total_block_io_read = thread_taskstats.blockIORead;
        self.stat.total_block_io_write = thread_taskstats.blockIOWrite;

        Ok(self.stat)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Process {
    // ids inside namespace
    pid: Pid,
    parent_pid: Pid,

    uid: Uid,
    effective_uid: Uid,
    saved_uid: Uid,
    fs_uid: Uid,

    gid: Gid,
    effective_gid: Gid,
    saved_gid: Gid,
    fs_gid: Gid,

    // ids outside namespace
    real_pid: Pid,
    real_parent_pid: Pid,

    real_uid: Uid,
    real_effective_uid: Uid,
    real_saved_uid: Uid,
    real_fs_uid: Uid,

    real_gid: Gid,
    real_effective_gid: Gid,
    real_saved_gid: Gid,
    real_fs_gid: Gid,

    exec_path: String,
    command: String,

    // accumulated thread stat of all threads of this process
    stat: ProcessStat,

    // accumulate process stat of all child process
    accumulated_childs_stat: ProcessStat,

    // stats + accumulatedChildsStats
    accumulated_stat: ProcessStat,

    // list of all threads
    threads: Vec<Thread>,

    // list of all child process
    childs: Vec<Process>,
}

#[allow(unused)]
impl Process {
    pub fn new(
        pid: Pid,
        parent_pid: Pid,
        uid: Uid,
        effective_uid: Uid,
        saved_uid: Uid,
        fs_uid: Uid,
        gid: Gid,
        effective_gid: Gid,
        saved_gid: Gid,
        fs_gid: Gid,
        real_pid: Pid,
        real_parent_pid: Pid,
        real_uid: Uid,
        real_effective_uid: Uid,
        real_saved_uid: Uid,
        real_fs_uid: Uid,
        real_gid: Gid,
        real_effective_gid: Gid,
        real_saved_gid: Gid,
        real_fs_gid: Gid,
        exec_path: String,
        command: String,
    ) -> Self {
        Self {
            pid,
            parent_pid,

            uid,
            effective_uid,
            saved_uid,
            fs_uid,

            gid,
            effective_gid,
            saved_gid,
            fs_gid,

            real_pid,
            real_parent_pid,

            real_uid,
            real_effective_uid,
            real_saved_uid,
            real_fs_uid,

            real_gid,
            real_effective_gid,
            real_saved_gid,
            real_fs_gid,

            exec_path,
            command,

            stat: ProcessStat::new(),
            accumulated_childs_stat: ProcessStat::new(),
            accumulated_stat: ProcessStat::new(),
            threads: Vec::new(),
            childs: Vec::new(),
        }
    }

    pub fn get_pid(&self) -> Pid {
        self.pid
    }
    pub fn get_parent_pid(&self) -> Pid {
        self.parent_pid
    }

    pub fn get_real_pid(&self) -> Pid {
        self.real_pid
    }
    pub fn get_real_parent_pid(&self) -> Pid {
        self.real_parent_pid
    }

    pub fn get_real_uid(&self) -> Uid {
        self.real_uid
    }
    pub fn get_real_effective_uid(&self) -> Uid {
        self.real_effective_uid
    }
    pub fn get_real_saved_uid(&self) -> Uid {
        self.real_saved_uid
    }
    pub fn get_real_fs_uid(&self) -> Uid {
        self.real_fs_uid
    }

    pub fn get_real_gid(&self) -> Gid {
        self.real_gid
    }
    pub fn get_real_effective_gid(&self) -> Gid {
        self.real_effective_gid
    }
    pub fn get_real_saved_gid(&self) -> Gid {
        self.real_saved_gid
    }
    pub fn get_real_fs_gid(&self) -> Gid {
        self.real_fs_gid
    }

    /// Build process tree, include all threads and childs
    pub fn build_proc_tree(
        &mut self,
        taskstats_conn: &mut TaskStatsConnection,
        net_rawstat: &mut NetworkRawStat,
    ) -> Result<ProcessStat, ProcessError> {
        // get global config
        let glob_conf = config::get_glob_conf().unwrap();

        // get memory usage
        let mem_data = fs::read_to_string(format!("/proc/{}/status", self.real_pid))?;
        let mem_data: Vec<&str> = mem_data.lines().collect();

        let (vss, rss, swap) = if glob_conf.is_old_kernel() {
            (
                mem_data[13].split_whitespace().collect::<Vec<&str>>()[1].parse::<usize>()?,
                mem_data[17].split_whitespace().collect::<Vec<&str>>()[1].parse::<usize>()?,
                mem_data[26].split_whitespace().collect::<Vec<&str>>()[1].parse::<usize>()?,
            )
        } else {
            (
                mem_data[17].split_whitespace().collect::<Vec<&str>>()[1].parse::<usize>()?,
                mem_data[21].split_whitespace().collect::<Vec<&str>>()[1].parse::<usize>()?,
                mem_data[30].split_whitespace().collect::<Vec<&str>>()[1].parse::<usize>()?,
            )
        };

        self.stat.total_vss += DataCount::from_kb(vss);
        self.stat.total_rss += DataCount::from_kb(rss);
        self.stat.total_swap += DataCount::from_kb(swap);

        // build network stat

        // get socket inode list
        let mut inodes = Vec::new();

        let fd_dir = match fs::read_dir(format!("/proc/{}/fd", self.real_pid)) {
            Ok(fd) => fd,
            Err(err) => return Err(ProcessError::IOErr(err)),
        };

        for fd in fd_dir {
            let fd = fd.unwrap();

            if let Ok(link) = fd.path().read_link() {
                let link = link.as_path().to_str().unwrap();
                if link.len() > 9 && &link[0..8] == "socket:[" {
                    inodes.push(Inode::try_from(&link[8..link.len() - 1]).unwrap());
                }
            }
        }

        // match inode to uniconnection stat
        for inode in inodes {
            if let Some(connection) = net_rawstat.LookupConnection(&inode) {
                let connection = connection.clone();

                if let Some(iname) = net_rawstat.LookupInterfaceName(&connection) {
                    let iname = iname.to_string();

                    let uni_conn = UniConnection::New(
                        connection.LocalAddr(),
                        connection.LocalPort(),
                        connection.RemoteAddr(),
                        connection.RemotePort(),
                        connection.ConnectionType(),
                    );

                    let reverse_uni_conn = UniConnection::New(
                        connection.RemoteAddr(),
                        connection.RemotePort(),
                        connection.LocalAddr(),
                        connection.LocalPort(),
                        connection.ConnectionType(),
                    );

                    // get interface raw stats
                    if let Some(irawstat) =
                        net_rawstat.get_irawstat(&iname)
                    {
                        // get 2 uniconnection stats from interface raw stat
                        let uni_conn_stat = irawstat
                            .get_uni_conn_stat(&uni_conn)
                            .unwrap_or(&UniConnectionStat::New(uni_conn))
                            .clone();

                        let reverse_uni_conn_stat = irawstat
                            .get_uni_conn_stat(&reverse_uni_conn)
                            .unwrap_or(&UniConnectionStat::New(reverse_uni_conn))
                            .clone();

                        // make new connection stat
                        let mut conn_stat = ConnectionStat::new(connection.clone());

                        conn_stat.pack_sent = uni_conn_stat.PacketCount();
                        conn_stat.pack_recv = reverse_uni_conn_stat.PacketCount();

                        conn_stat.total_data_sent = uni_conn_stat.TotalDataCount();
                        conn_stat.total_data_recv = reverse_uni_conn_stat.TotalDataCount();

                        conn_stat.real_data_sent = uni_conn_stat.RealDataCount();
                        conn_stat.real_data_recv = reverse_uni_conn_stat.RealDataCount();

                        // add new connection stat to interface stat
                        self.stat
                            .netstat
                            .add_conn_stat(&iname, conn_stat);
                    }
                }
            }
        }

        // update threads list
        let task_dir = match fs::read_dir(format!("/proc/{}/task", self.real_pid)) {
            Ok(dir) => dir,
            Err(err) => return Err(ProcessError::IOErr(err)),
        };

        for thread_dir in task_dir {
            let thread_dir = thread_dir.unwrap();

            if thread_dir.file_type().unwrap().is_dir() {
                if let Ok(real_tid) = Tid::try_from(thread_dir.file_name().to_str().unwrap()) {
                    // get tid
                    let thread_status_file_content = match fs::read_to_string(format!(
                        "{}/status",
                        thread_dir.path().to_str().unwrap()
                    )) {
                        Ok(content) => content,
                        Err(_) => continue,
                    };

                    let thread_lines: Vec<&str> = thread_status_file_content.lines().collect();

                    // get tid
                    let tid = if glob_conf.is_old_kernel() {
                        Tid::new(0)
                    } else {
                        let tids = thread_lines[13].split_whitespace().collect::<Vec<&str>>();
                        Tid::try_from(tids[tids.len() - 1]).unwrap()
                    };

                    let mut new_thread = Thread::new(tid, self.pid, real_tid, self.real_pid);

                    if let Ok(thread_stat) = new_thread.get_stat(taskstats_conn) {
                        self.stat += thread_stat;

                        // add new thread
                        self.threads.push(new_thread);
                    }
                }
            }
        }

        // from here can fail and still return the stats
        self.accumulated_stat = self.stat.clone();

        // update child list
        let children_list = match fs::read_to_string(format!(
            "/proc/{}/task/{}/children",
            self.real_pid, self.real_pid
        )) {
            Ok(list) => list,
            Err(_) => return Ok(self.accumulated_stat.clone()),
        };

        for child_real_pid in children_list.split_terminator(" ") {
            let mut child_proc = match get_real_proc(&Pid::try_from(child_real_pid).unwrap()) {
                Ok(child) => child,
                Err(_) => return Ok(self.accumulated_stat.clone()),
            };

            // build the child thread and process list
            let child_stat = match child_proc.build_proc_tree(taskstats_conn, net_rawstat)
            {
                Ok(stat) => stat,
                Err(_) => return Ok(self.accumulated_stat.clone()),
            };

            self.accumulated_childs_stat += child_stat;

            // add the child to this process child list
            self.childs.push(child_proc);
        }

        self.accumulated_stat = self.stat.clone() + self.accumulated_childs_stat.clone();

        Ok(self.accumulated_stat.clone())
    }
}

#[derive(Debug, Clone, Copy)]
#[allow(unused)]
struct UidMapEntry {
    uid_start: Uid,
    uid_end: Uid,
    real_uid_start: Uid,
    real_uid_end: Uid,
    length: usize,
}

impl UidMapEntry {
    pub fn new(uid_start: Uid, real_uid_start: Uid, length: usize) -> Self {
        Self {
            uid_start,
            uid_end: Uid::new(uid_start.to_usize() + length),
            real_uid_start,
            real_uid_end: Uid::new(real_uid_start.to_usize() + length),
            length,
        }
    }

    pub fn map_to_uid(&self, real_uid: Uid) -> Option<Uid> {
        if real_uid >= self.real_uid_start && real_uid <= self.real_uid_end {
            Some(Uid::new(
                self.uid_start.to_usize() + real_uid.to_usize() - self.real_uid_start.to_usize(),
            ))
        } else {
            None
        }
    }
}

impl TryFrom<&str> for UidMapEntry {
    type Error = ProcessError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let values: Vec<usize> = value
            .trim()
            .split_whitespace()
            .map(|x| x.parse().unwrap())
            .collect();

        if values.len() != 3 {
            return Err(ProcessError::UIDMapErr);
        }

        let start = Uid::new(values[0]);
        let real_start = Uid::new(values[1]);
        let length = values[2];

        // check length
        if length <= 0 {
            return Err(ProcessError::UIDMapErr);
        }

        Ok(Self::new(start, real_start, length))
    }
}

#[derive(Debug, Clone)]
struct UidMap {
    uid_map_entries: Vec<UidMapEntry>,
}

impl UidMap {
    pub fn new() -> Self {
        Self {
            uid_map_entries: Vec::new(),
        }
    }

    pub fn map_to_uid(&self, real_uid: Uid) -> Option<Uid> {
        for uid_map_entry in &self.uid_map_entries {
            if let Some(uid) = uid_map_entry.map_to_uid(real_uid) {
                return Some(uid);
            }
        }

        None
    }
}

impl TryFrom<&str> for UidMap {
    type Error = ProcessError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut result = Self::new();

        for line in value.lines() {
            let new_uid_map_entry = UidMapEntry::try_from(line)?;

            // check for overlapping
            for uid_map_entry in &result.uid_map_entries {
                // if overlap, error
                if new_uid_map_entry.uid_start >= uid_map_entry.uid_start
                    && new_uid_map_entry.uid_start <= uid_map_entry.uid_end
                {
                    return Err(ProcessError::UIDMapErr);
                }

                if new_uid_map_entry.uid_end >= uid_map_entry.uid_start
                    && new_uid_map_entry.uid_end <= uid_map_entry.uid_end
                {
                    return Err(ProcessError::UIDMapErr);
                }
            }

            // check done
            result.uid_map_entries.push(new_uid_map_entry);
        }

        Ok(result)
    }
}

#[derive(Debug, Clone, Copy)]
#[allow(unused)]
struct GidMapEntry {
    gid_start: Gid,
    gid_end: Gid,
    real_gid_start: Gid,
    real_gid_end: Gid,
    length: usize,
}

impl GidMapEntry {
    pub fn new(gid_start: Gid, real_gid_start: Gid, length: usize) -> Self {
        Self {
            gid_start,
            gid_end: Gid::new(gid_start.to_usize() + length),
            real_gid_start,
            real_gid_end: Gid::new(real_gid_start.to_usize() + length),
            length,
        }
    }

    pub fn map_to_gid(&self, real_gid: Gid) -> Option<Gid> {
        if real_gid >= self.real_gid_start && real_gid <= self.real_gid_end {
            Some(Gid::new(
                self.gid_start.to_usize() + real_gid.to_usize() - self.real_gid_start.to_usize(),
            ))
        } else {
            None
        }
    }
}

impl TryFrom<&str> for GidMapEntry {
    type Error = ProcessError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let values: Vec<usize> = value
            .trim()
            .split_whitespace()
            .map(|x| x.parse().unwrap())
            .collect();

        if values.len() != 3 {
            return Err(ProcessError::GIDMapErr);
        }

        let start = Gid::new(values[0]);
        let real_start = Gid::new(values[1]);
        let length = values[2];

        // check length
        if length <= 0 {
            return Err(ProcessError::GIDMapErr);
        }

        Ok(Self::new(start, real_start, length))
    }
}

#[derive(Debug, Clone)]
struct GidMap {
    gid_map_entries: Vec<GidMapEntry>,
}

impl GidMap {
    pub fn new() -> Self {
        Self {
            gid_map_entries: Vec::new(),
        }
    }

    pub fn map_to_gid(&self, real_gid: Gid) -> Option<Gid> {
        for gid_map_entry in &self.gid_map_entries {
            if let Some(gid) = gid_map_entry.map_to_gid(real_gid) {
                return Some(gid);
            }
        }

        None
    }
}

impl TryFrom<&str> for GidMap {
    type Error = ProcessError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut result = Self::new();

        for line in value.lines() {
            let new_gid_map_entry = GidMapEntry::try_from(line)?;

            // check for overlapping
            for gid_map_entry in &result.gid_map_entries {
                // if overlap, error
                if new_gid_map_entry.gid_start >= gid_map_entry.gid_start
                    && new_gid_map_entry.gid_start <= gid_map_entry.gid_end
                {
                    return Err(ProcessError::GIDMapErr);
                }

                if new_gid_map_entry.gid_end >= gid_map_entry.gid_start
                    && new_gid_map_entry.gid_end <= gid_map_entry.gid_end
                {
                    return Err(ProcessError::GIDMapErr);
                }
            }

            // check done
            result.gid_map_entries.push(new_gid_map_entry);
        }

        Ok(result)
    }
}

/// Make a process from realPid, with all data pulled from running system
pub fn get_real_proc(real_pid: &Pid) -> Result<Process, ProcessError> {
    let status_file_content = fs::read_to_string(format!("/proc/{}/status", real_pid))?;
    let lines: Vec<&str> = status_file_content.lines().collect();

    // get global config
    let glob_conf = config::get_glob_conf().unwrap();

    // get pid
    let pid = if glob_conf.is_old_kernel() {
        Pid::new(0)
    } else {
        let pids = lines[12].split_whitespace().collect::<Vec<&str>>();
        Pid::try_from(pids[pids.len() - 1]).unwrap()
    };

    // get realParentPid
    let real_parent_pid = if *real_pid == Pid::new(1) {
        Pid::new(0)
    } else {
        Pid::try_from(lines[6].split_whitespace().collect::<Vec<&str>>()[1])?
    };

    // get parentPid
    let parent_pid = if glob_conf.is_old_kernel() {
        Pid::new(0)
    } else if *real_pid == Pid::new(1) {
        Pid::new(0)
    } else {
        let parent_status_file_content =
            fs::read_to_string(format!("/proc/{}/status", real_parent_pid))?;

        let parent_lines: Vec<&str> = parent_status_file_content.lines().collect();
        let parent_pids = parent_lines[12].split_whitespace().collect::<Vec<&str>>();

        if pid != Pid::new(1) {
            Pid::try_from(parent_pids[parent_pids.len() - 1])?
        } else {
            Pid::new(0)
        }
    };

    // get real uids and gids
    let real_uids = lines[8].split_whitespace().collect::<Vec<&str>>();
    let real_gids = lines[9].split_whitespace().collect::<Vec<&str>>();

    let real_uid = Uid::try_from(real_uids[1]).unwrap();
    let real_effective_uid = Uid::try_from(real_uids[2]).unwrap();
    let real_saved_uid = Uid::try_from(real_uids[3]).unwrap();
    let real_fs_uid = Uid::try_from(real_uids[4]).unwrap();

    let real_gid = Gid::try_from(real_gids[1]).unwrap();
    let real_effective_gid = Gid::try_from(real_gids[2]).unwrap();
    let real_saved_gid = Gid::try_from(real_gids[3]).unwrap();
    let real_fs_gid = Gid::try_from(real_gids[4]).unwrap();

    // map real uids and real gids to uids and gids
    let uid_map =
        UidMap::try_from(fs::read_to_string(format!("/proc/{}/uid_map", real_pid))?.as_str())?;
    let gid_map =
        GidMap::try_from(fs::read_to_string(format!("/proc/{}/gid_map", real_pid))?.as_str())?;

    // map every real id to id
    let uid = uid_map.map_to_uid(real_uid).unwrap();
    let effective_uid = uid_map.map_to_uid(real_effective_uid).unwrap();
    let saved_uid = uid_map.map_to_uid(real_saved_uid).unwrap();
    let fs_uid = uid_map.map_to_uid(real_fs_uid).unwrap();

    let gid = gid_map.map_to_gid(real_gid).unwrap();
    let effective_gid = gid_map.map_to_gid(real_effective_gid).unwrap();
    let saved_gid = gid_map.map_to_gid(real_saved_gid).unwrap();
    let fs_gid = gid_map.map_to_gid(real_fs_gid).unwrap();

    // get execution path
    let exec_path = fs::read_link(format!("/proc/{}/exe", real_pid))?;
    let exec_path = exec_path.as_path().to_str().unwrap().to_string();

    // get command
    let command = fs::read_to_string(format!("/proc/{}/comm", real_pid))?;

    Ok(Process::new(
        pid,
        parent_pid,
        uid,
        effective_uid,
        saved_uid,
        fs_uid,
        gid,
        effective_gid,
        saved_gid,
        fs_gid,
        *real_pid,
        real_parent_pid,
        real_uid,
        real_effective_uid,
        real_saved_uid,
        real_fs_uid,
        real_gid,
        real_effective_gid,
        real_saved_gid,
        real_fs_gid,
        exec_path,
        command,
    ))
}

#[derive(Debug)]
pub enum ProcessError {
    IOErr(io::Error),
    TaskstatsErr(TaskStatsError),
    ParseIntErr(std::num::ParseIntError),
    UIDMapErr,
    GIDMapErr,
    CommonErr(CommonError),
}

impl std::error::Error for ProcessError {}

impl fmt::Display for ProcessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let result = match self {
            Self::IOErr(error) => String::from(format!("IO error: {}", error)),
            Self::TaskstatsErr(error) => String::from(format!("Taskstats error: {}", error)),
            Self::ParseIntErr(error) => String::from(format!("Parse integer error: {}", error)),
            Self::UIDMapErr => String::from(format!("Uid map error")),
            Self::GIDMapErr => String::from(format!("Gid map error")),
            Self::CommonErr(error) => String::from(format!("Common error: {}", error)),
        };

        write!(f, "{}", result)
    }
}

impl From<TaskStatsError> for ProcessError {
    fn from(error: TaskStatsError) -> Self {
        Self::TaskstatsErr(error)
    }
}

impl From<io::Error> for ProcessError {
    fn from(error: io::Error) -> Self {
        Self::IOErr(error)
    }
}

impl From<std::num::ParseIntError> for ProcessError {
    fn from(error: std::num::ParseIntError) -> Self {
        Self::ParseIntErr(error)
    }
}

impl From<CommonError> for ProcessError {
    fn from(error: CommonError) -> Self {
        Self::CommonErr(error)
    }
}
