use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::ops::{Add, AddAssign};
use std::{fmt, fs, io};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::common::{CommonError, Count, DataCount, Gid, Inode, TimeCount, Timestamp, Uid};
use crate::config;
use crate::taskstat::{TaskStatsConnection, TaskStatsError};
use crate::NetworkStat::{Connection, NetworkRawStat, UniConnection, UniConnectionStat};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
pub struct Pid(u128);

impl Pid {
    pub fn New(pid: usize) -> Self {
        Self(pid.try_into().unwrap())
    }
    pub fn Usize(&self) -> usize {
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
        Ok(Pid::New(Deserialize::deserialize(deserializer)?))
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
pub struct Tid(u128);

impl Tid {
    pub fn New(tid: usize) -> Self {
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
    packetSent: Count,
    packetRecv: Count,

    // data count in link layer
    totalDataSent: DataCount,
    totalDataRecv: DataCount,

    // data count in higher level
    realDataSent: DataCount,
    realDataRecv: DataCount,
}

impl ConnectionStat {
    pub fn New(connection: Connection) -> Self {
        Self {
            connection,

            packetSent: Count::new(0),
            packetRecv: Count::new(0),

            totalDataSent: DataCount::from_byte(0),
            totalDataRecv: DataCount::from_byte(0),

            realDataSent: DataCount::from_byte(0),
            realDataRecv: DataCount::from_byte(0),
        }
    }

    pub fn Connection(&self) -> Connection {
        self.connection
    }

    pub fn PacketSent(&self) -> Count {
        self.packetSent
    }

    pub fn PacketRecv(&self) -> Count {
        self.packetRecv
    }

    pub fn TotalDataSent(&self) -> DataCount {
        self.totalDataSent
    }

    pub fn TotalDataRecv(&self) -> DataCount {
        self.totalDataRecv
    }

    pub fn RealDataSent(&self) -> DataCount {
        self.realDataSent
    }

    pub fn RealDataRecv(&self) -> DataCount {
        self.realDataRecv
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

            packetSent: self.packetSent + other.packetSent,
            packetRecv: self.packetRecv + other.packetRecv,

            totalDataSent: self.totalDataSent + other.totalDataSent,
            totalDataRecv: self.totalDataRecv + other.totalDataRecv,

            realDataSent: self.realDataSent + other.realDataSent,
            realDataRecv: self.realDataRecv + other.realDataRecv,
        }
    }
}

impl AddAssign<Self> for ConnectionStat {
    fn add_assign(&mut self, other: Self) {
        assert!(
            self.connection == other.connection,
            "Can't add different connections!"
        );

        self.packetSent += other.packetSent;
        self.packetRecv += other.packetRecv;

        self.totalDataSent += other.totalDataSent;
        self.totalDataRecv += other.totalDataRecv;

        self.realDataSent += other.realDataSent;
        self.realDataRecv += other.realDataRecv;
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct InterfaceStat {
    interfaceName: String,

    // packet count
    packetSent: Count,
    packetRecv: Count,

    // data count in link layer
    totalDataSent: DataCount,
    totalDataRecv: DataCount,

    // data count in higher level
    realDataSent: DataCount,
    realDataRecv: DataCount,

    // map from Connection to ConnectionStat
    #[serde(serialize_with = "InterfaceStatConnectionStatsSerialize")]
    connectionStats: HashMap<Connection, ConnectionStat>,
}

impl InterfaceStat {
    pub fn New(interfaceName: &str) -> Self {
        Self {
            interfaceName: String::from(interfaceName),

            packetSent: Count::new(0),
            packetRecv: Count::new(0),

            totalDataSent: DataCount::from_byte(0),
            totalDataRecv: DataCount::from_byte(0),

            realDataSent: DataCount::from_byte(0),
            realDataRecv: DataCount::from_byte(0),

            connectionStats: HashMap::new(),
        }
    }

    pub fn Name(&self) -> String {
        self.interfaceName.clone()
    }

    pub fn AddConnectionStat(&mut self, connectionStat: ConnectionStat) {
        self.packetSent += connectionStat.PacketSent();
        self.packetRecv += connectionStat.PacketRecv();

        self.totalDataSent += connectionStat.TotalDataSent();
        self.totalDataRecv += connectionStat.TotalDataRecv();

        self.realDataSent += connectionStat.RealDataSent();
        self.realDataRecv += connectionStat.RealDataRecv();

        self.connectionStats
            .insert(connectionStat.Connection(), connectionStat);
    }
}

impl Add<Self> for InterfaceStat {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        assert!(
            self.interfaceName == other.interfaceName,
            "Can't add different interface stats!"
        );

        let mut result = Self::New(&self.interfaceName);

        result.packetSent = self.packetSent + other.packetSent;
        result.packetRecv = self.packetRecv + other.packetRecv;

        result.totalDataSent = self.totalDataSent + other.totalDataSent;
        result.totalDataRecv = self.totalDataRecv + other.totalDataRecv;

        result.realDataSent = self.realDataSent + other.realDataSent;
        result.realDataRecv = self.realDataRecv + other.realDataRecv;

        // merge connectionStats
        result.connectionStats = self.connectionStats;

        for (otherConnection, otherConnectionStat) in other.connectionStats {
            if let Some(connectionStat) = result.connectionStats.get_mut(&otherConnection) {
                *connectionStat += otherConnectionStat;
            } else {
                result
                    .connectionStats
                    .insert(otherConnection, otherConnectionStat);
            }
        }

        result
    }
}

impl AddAssign<Self> for InterfaceStat {
    fn add_assign(&mut self, other: Self) {
        assert!(
            self.interfaceName == other.interfaceName,
            "Can't add different interface stats!"
        );

        self.packetSent += other.packetSent;
        self.packetRecv += other.packetRecv;

        self.totalDataSent += other.totalDataSent;
        self.totalDataRecv += other.totalDataRecv;

        self.realDataSent += other.realDataSent;
        self.realDataRecv += other.realDataRecv;

        // merge connectionStats
        for (otherConnection, otherConnectionStat) in other.connectionStats {
            if let Some(connectionStat) = self.connectionStats.get_mut(&otherConnection) {
                *connectionStat += otherConnectionStat;
            } else {
                self.connectionStats
                    .insert(otherConnection, otherConnectionStat);
            }
        }
    }
}

fn InterfaceStatConnectionStatsSerialize<S: Serializer>(
    input: &HashMap<Connection, ConnectionStat>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(input.values())
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkStat {
    // packet count
    packetSent: Count,
    packetRecv: Count,

    // data count in link layer
    totalDataSent: DataCount,
    totalDataRecv: DataCount,

    // data count in higher level
    realDataSent: DataCount,
    realDataRecv: DataCount,

    // map from InterfaceName to InterfaceStat
    #[serde(serialize_with = "NetworkStatInterfaceStatsSerialize")]
    interfaceStats: HashMap<String, InterfaceStat>,
}

impl NetworkStat {
    pub fn New() -> Self {
        Self {
            packetSent: Count::new(0),
            packetRecv: Count::new(0),

            totalDataSent: DataCount::from_byte(0),
            totalDataRecv: DataCount::from_byte(0),

            realDataSent: DataCount::from_byte(0),
            realDataRecv: DataCount::from_byte(0),

            interfaceStats: HashMap::new(),
        }
    }

    pub fn AddConnectionStat(&mut self, interfaceName: &str, connectionStat: ConnectionStat) {
        self.packetSent += connectionStat.PacketSent();
        self.packetRecv += connectionStat.PacketRecv();

        self.totalDataSent += connectionStat.TotalDataSent();
        self.totalDataRecv += connectionStat.TotalDataRecv();

        self.realDataSent += connectionStat.RealDataSent();
        self.realDataRecv += connectionStat.RealDataRecv();

        // create interface stat if not existed yet
        if !self.interfaceStats.contains_key(interfaceName) {
            self.interfaceStats
                .insert(interfaceName.to_string(), InterfaceStat::New(interfaceName));
        }

        // insert the stat to interface stat
        self.interfaceStats
            .get_mut(interfaceName)
            .unwrap()
            .AddConnectionStat(connectionStat);
    }
}

impl Add<Self> for NetworkStat {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let mut result = Self::New();

        result.packetSent = self.packetSent + other.packetSent;
        result.packetRecv = self.packetRecv + other.packetRecv;

        result.totalDataSent = self.totalDataSent + other.totalDataSent;
        result.totalDataRecv = self.totalDataRecv + other.totalDataRecv;

        result.realDataSent = self.realDataSent + other.realDataSent;
        result.realDataRecv = self.realDataRecv + other.realDataRecv;

        // merge interfaceStats
        result.interfaceStats = self.interfaceStats;

        for (otherInterfaceName, otherInterfaceStat) in other.interfaceStats {
            if let Some(interfaceStat) = result.interfaceStats.get_mut(&otherInterfaceName) {
                *interfaceStat += otherInterfaceStat;
            } else {
                result
                    .interfaceStats
                    .insert(otherInterfaceName, otherInterfaceStat);
            }
        }

        result
    }
}

impl AddAssign<Self> for NetworkStat {
    fn add_assign(&mut self, other: Self) {
        self.packetSent += other.packetSent;
        self.packetRecv += other.packetRecv;

        self.totalDataSent += other.totalDataSent;
        self.totalDataRecv += other.totalDataRecv;

        self.realDataSent += other.realDataSent;
        self.realDataRecv += other.realDataRecv;

        // merge interfaceStats
        for (otherInterfaceName, otherInterfaceStat) in other.interfaceStats {
            if let Some(interfaceStat) = self.interfaceStats.get_mut(&otherInterfaceName) {
                *interfaceStat += otherInterfaceStat;
            } else {
                self.interfaceStats
                    .insert(otherInterfaceName, otherInterfaceStat);
            }
        }
    }
}

fn NetworkStatInterfaceStatsSerialize<S: Serializer>(
    input: &HashMap<String, InterfaceStat>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(input.values())
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct ThreadStat {
    timestamp: Timestamp,

    totalSystemCpuTime: TimeCount,
    totalUserCpuTime: TimeCount,
    totalCpuTime: TimeCount,

    totalIORead: DataCount,
    totalIOWrite: DataCount,

    totalBlockIORead: DataCount,
    totalBlockIOWrite: DataCount,
}

impl ThreadStat {
    pub fn New() -> Self {
        Self {
            timestamp: Timestamp::get_curr_timestamp(),

            totalSystemCpuTime: TimeCount::from_secs(0),
            totalUserCpuTime: TimeCount::from_secs(0),
            totalCpuTime: TimeCount::from_secs(0),

            totalIORead: DataCount::from_byte(0),
            totalIOWrite: DataCount::from_byte(0),

            totalBlockIORead: DataCount::from_byte(0),
            totalBlockIOWrite: DataCount::from_byte(0),
        }
    }

    pub fn TotalSystemCpuTime(&self) -> TimeCount {
        self.totalSystemCpuTime
    }
    pub fn TotalUserCpuTime(&self) -> TimeCount {
        self.totalUserCpuTime
    }
    pub fn TotalCpuTime(&self) -> TimeCount {
        self.totalCpuTime
    }

    pub fn TotalIORead(&self) -> DataCount {
        self.totalIORead
    }
    pub fn TotalIOWrite(&self) -> DataCount {
        self.totalIOWrite
    }

    pub fn TotalBlockIORead(&self) -> DataCount {
        self.totalBlockIORead
    }
    pub fn TotalBlockIOWrite(&self) -> DataCount {
        self.totalBlockIOWrite
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ProcessStat {
    timestamp: Timestamp,

    totalSystemCpuTime: TimeCount,
    totalUserCpuTime: TimeCount,
    totalCpuTime: TimeCount,

    totalRss: DataCount,
    totalVss: DataCount,
    totalSwap: DataCount,

    totalIORead: DataCount,
    totalIOWrite: DataCount,

    totalBlockIORead: DataCount,
    totalBlockIOWrite: DataCount,

    networkStat: NetworkStat,
}

impl ProcessStat {
    pub fn New() -> Self {
        Self {
            timestamp: Timestamp::get_curr_timestamp(),

            totalSystemCpuTime: TimeCount::from_secs(0),
            totalUserCpuTime: TimeCount::from_secs(0),
            totalCpuTime: TimeCount::from_secs(0),

            totalRss: DataCount::from_byte(0),
            totalVss: DataCount::from_byte(0),
            totalSwap: DataCount::from_byte(0),

            totalIORead: DataCount::from_byte(0),
            totalIOWrite: DataCount::from_byte(0),

            totalBlockIORead: DataCount::from_byte(0),
            totalBlockIOWrite: DataCount::from_byte(0),

            networkStat: NetworkStat::New(),
        }
    }
}

impl Add<Self> for ProcessStat {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self {
            timestamp: self.timestamp,

            totalSystemCpuTime: self.totalSystemCpuTime + other.totalSystemCpuTime,
            totalUserCpuTime: self.totalUserCpuTime + other.totalUserCpuTime,
            totalCpuTime: self.totalCpuTime + other.totalCpuTime,

            totalRss: self.totalRss + other.totalRss,
            totalVss: self.totalVss + other.totalVss,
            totalSwap: self.totalSwap + other.totalSwap,

            totalIORead: self.totalIORead + other.totalIORead,
            totalIOWrite: self.totalIOWrite + other.totalIOWrite,

            totalBlockIORead: self.totalBlockIORead + other.totalBlockIORead,
            totalBlockIOWrite: self.totalBlockIOWrite + other.totalBlockIOWrite,

            networkStat: self.networkStat + other.networkStat,
        }
    }
}

impl Add<ThreadStat> for ProcessStat {
    type Output = Self;

    fn add(self, other: ThreadStat) -> Self {
        Self {
            timestamp: self.timestamp,

            totalSystemCpuTime: self.totalSystemCpuTime + other.TotalSystemCpuTime(),
            totalUserCpuTime: self.totalUserCpuTime + other.TotalUserCpuTime(),
            totalCpuTime: self.totalCpuTime + other.TotalCpuTime(),

            totalRss: self.totalRss,
            totalVss: self.totalVss,
            totalSwap: self.totalSwap,

            totalIORead: self.totalIORead + other.TotalIORead(),
            totalIOWrite: self.totalIOWrite + other.TotalIOWrite(),

            totalBlockIORead: self.totalBlockIORead + other.TotalBlockIORead(),
            totalBlockIOWrite: self.totalBlockIOWrite + other.TotalBlockIOWrite(),

            networkStat: self.networkStat,
        }
    }
}

impl AddAssign<Self> for ProcessStat {
    fn add_assign(&mut self, other: Self) {
        self.totalSystemCpuTime += other.totalSystemCpuTime;
        self.totalUserCpuTime += other.totalUserCpuTime;
        self.totalCpuTime += other.totalCpuTime;

        self.totalRss += other.totalRss;
        self.totalVss += other.totalVss;
        self.totalSwap += other.totalSwap;

        self.totalIORead += other.totalIORead;
        self.totalIOWrite += other.totalIOWrite;

        self.totalBlockIORead += other.totalBlockIORead;
        self.totalBlockIOWrite += other.totalBlockIOWrite;

        self.networkStat += other.networkStat;
    }
}

impl AddAssign<ThreadStat> for ProcessStat {
    fn add_assign(&mut self, other: ThreadStat) {
        self.totalSystemCpuTime += other.TotalSystemCpuTime();
        self.totalUserCpuTime += other.TotalUserCpuTime();
        self.totalCpuTime += other.TotalCpuTime();

        self.totalIORead += other.TotalIORead();
        self.totalIOWrite += other.TotalIOWrite();

        self.totalBlockIORead += other.TotalBlockIORead();
        self.totalBlockIOWrite += other.TotalBlockIOWrite();
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Thread {
    // ids inside namespace
    tid: Tid,
    pid: Pid,

    // ids outside namespace
    realTid: Tid,
    realPid: Pid,

    // this thread stat
    stat: ThreadStat,
}

impl Thread {
    pub fn New(tid: Tid, pid: Pid, realTid: Tid, realPid: Pid) -> Self {
        Self {
            tid,
            pid,

            realTid,
            realPid,

            stat: ThreadStat::New(),
        }
    }

    pub fn Tid(&self) -> Tid {
        self.tid
    }
    pub fn Pid(&self) -> Pid {
        self.pid
    }

    pub fn RealTid(&self) -> Tid {
        self.realTid
    }
    pub fn RealPid(&self) -> Pid {
        self.realPid
    }

    // update this thread stat, and return a copy of it
    pub fn GetStat(
        &mut self,
        taskStatsConnection: &mut TaskStatsConnection,
    ) -> Result<ThreadStat, ProcessError> {
        let threadTaskStats = taskStatsConnection.GetThreadTaskStats(self.realTid)?;

        self.stat.totalSystemCpuTime = threadTaskStats.systemCpuTime;
        self.stat.totalUserCpuTime = threadTaskStats.userCpuTime;
        self.stat.totalCpuTime = threadTaskStats.systemCpuTime + threadTaskStats.userCpuTime;

        self.stat.totalIORead = threadTaskStats.ioRead;
        self.stat.totalIOWrite = threadTaskStats.ioWrite;

        self.stat.totalBlockIORead = threadTaskStats.blockIORead;
        self.stat.totalBlockIOWrite = threadTaskStats.blockIOWrite;

        Ok(self.stat)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Process {
    // ids inside namespace
    pid: Pid,
    parentPid: Pid,

    uid: Uid,
    effectiveUid: Uid,
    savedUid: Uid,
    fsUid: Uid,

    gid: Gid,
    effectiveGid: Gid,
    savedGid: Gid,
    fsGid: Gid,

    // ids outside namespace
    realPid: Pid,
    realParentPid: Pid,

    realUid: Uid,
    realEffectiveUid: Uid,
    realSavedUid: Uid,
    realFsUid: Uid,

    realGid: Gid,
    realEffectiveGid: Gid,
    realSavedGid: Gid,
    realFsGid: Gid,

    executionPath: String,
    command: String,

    // accumulated thread stat of all threads of this process
    stat: ProcessStat,

    // accumulate process stat of all child process
    accumulatedChildsStat: ProcessStat,

    // stats + accumulatedChildsStats
    accumulatedStat: ProcessStat,

    // list of all threads
    threads: Vec<Thread>,

    // list of all child process
    childs: Vec<Process>,
}

impl Process {
    pub fn New(
        pid: Pid,
        parentPid: Pid,
        uid: Uid,
        effectiveUid: Uid,
        savedUid: Uid,
        fsUid: Uid,
        gid: Gid,
        effectiveGid: Gid,
        savedGid: Gid,
        fsGid: Gid,
        realPid: Pid,
        realParentPid: Pid,
        realUid: Uid,
        realEffectiveUid: Uid,
        realSavedUid: Uid,
        realFsUid: Uid,
        realGid: Gid,
        realEffectiveGid: Gid,
        realSavedGid: Gid,
        realFsGid: Gid,
        executionPath: String,
        command: String,
    ) -> Self {
        Self {
            pid,
            parentPid,

            uid,
            effectiveUid,
            savedUid,
            fsUid,

            gid,
            effectiveGid,
            savedGid,
            fsGid,

            realPid,
            realParentPid,

            realUid,
            realEffectiveUid,
            realSavedUid,
            realFsUid,

            realGid,
            realEffectiveGid,
            realSavedGid,
            realFsGid,

            executionPath,
            command,

            stat: ProcessStat::New(),
            accumulatedChildsStat: ProcessStat::New(),
            accumulatedStat: ProcessStat::New(),
            threads: Vec::new(),
            childs: Vec::new(),
        }
    }

    pub fn Pid(&self) -> Pid {
        self.pid
    }
    pub fn ParentPid(&self) -> Pid {
        self.parentPid
    }

    pub fn RealPid(&self) -> Pid {
        self.realPid
    }
    pub fn RealParentPid(&self) -> Pid {
        self.realParentPid
    }

    pub fn RealUid(&self) -> Uid {
        self.realUid
    }
    pub fn RealEffectiveUid(&self) -> Uid {
        self.realEffectiveUid
    }
    pub fn RealSavedUid(&self) -> Uid {
        self.realSavedUid
    }
    pub fn RealFsUid(&self) -> Uid {
        self.realFsUid
    }

    pub fn RealGid(&self) -> Gid {
        self.realGid
    }
    pub fn RealEffectiveGid(&self) -> Gid {
        self.realEffectiveGid
    }
    pub fn RealSavedGid(&self) -> Gid {
        self.realSavedGid
    }
    pub fn RealFsGid(&self) -> Gid {
        self.realFsGid
    }

    /// Build process tree, include all threads and childs
    pub fn BuildProcessTree(
        &mut self,
        taskStatsConnection: &mut TaskStatsConnection,
        networkRawStat: &mut NetworkRawStat,
    ) -> Result<ProcessStat, ProcessError> {
        // get global config
        let globalConfig = config::GetGlobalConfig().unwrap();

        // get memory usage
        let memData = fs::read_to_string(format!("/proc/{}/status", self.realPid))?;
        let memData: Vec<&str> = memData.lines().collect();

        let (vss, rss, swap) = if globalConfig.IsOldKernel() {
            (
                memData[13].split_whitespace().collect::<Vec<&str>>()[1].parse::<usize>()?,
                memData[17].split_whitespace().collect::<Vec<&str>>()[1].parse::<usize>()?,
                memData[26].split_whitespace().collect::<Vec<&str>>()[1].parse::<usize>()?,
            )
        } else {
            (
                memData[17].split_whitespace().collect::<Vec<&str>>()[1].parse::<usize>()?,
                memData[21].split_whitespace().collect::<Vec<&str>>()[1].parse::<usize>()?,
                memData[30].split_whitespace().collect::<Vec<&str>>()[1].parse::<usize>()?,
            )
        };

        self.stat.totalVss += DataCount::from_kb(vss);
        self.stat.totalRss += DataCount::from_kb(rss);
        self.stat.totalSwap += DataCount::from_kb(swap);

        // build network stat

        // get socket inode list
        let mut inodes = Vec::new();

        let fdDir = match fs::read_dir(format!("/proc/{}/fd", self.realPid)) {
            Ok(fd) => fd,
            Err(err) => return Err(ProcessError::IO_ERROR(err)),
        };

        for fd in fdDir {
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
            if let Some(connection) = networkRawStat.LookupConnection(&inode) {
                let connection = connection.clone();

                if let Some(interfaceName) = networkRawStat.LookupInterfaceName(&connection) {
                    let interfaceName = interfaceName.to_string();

                    let uniConnection = UniConnection::New(
                        connection.LocalAddr(),
                        connection.LocalPort(),
                        connection.RemoteAddr(),
                        connection.RemotePort(),
                        connection.ConnectionType(),
                    );

                    let reverseUniConnection = UniConnection::New(
                        connection.RemoteAddr(),
                        connection.RemotePort(),
                        connection.LocalAddr(),
                        connection.LocalPort(),
                        connection.ConnectionType(),
                    );

                    // get interface raw stats
                    if let Some(interfaceRawStat) =
                        networkRawStat.GetInterfaceRawStat(&interfaceName)
                    {
                        // get 2 uniconnection stats from interface raw stat
                        let uniConnectionStat = interfaceRawStat
                            .GetUniConnectionStat(&uniConnection)
                            .unwrap_or(&UniConnectionStat::New(uniConnection))
                            .clone();

                        let reverseUniConnectionStat = interfaceRawStat
                            .GetUniConnectionStat(&reverseUniConnection)
                            .unwrap_or(&UniConnectionStat::New(reverseUniConnection))
                            .clone();

                        // make new connection stat
                        let mut connectionStat = ConnectionStat::New(connection.clone());

                        connectionStat.packetSent = uniConnectionStat.PacketCount();
                        connectionStat.packetRecv = reverseUniConnectionStat.PacketCount();

                        connectionStat.totalDataSent = uniConnectionStat.TotalDataCount();
                        connectionStat.totalDataRecv = reverseUniConnectionStat.TotalDataCount();

                        connectionStat.realDataSent = uniConnectionStat.RealDataCount();
                        connectionStat.realDataRecv = reverseUniConnectionStat.RealDataCount();

                        // add new connection stat to interface stat
                        self.stat
                            .networkStat
                            .AddConnectionStat(&interfaceName, connectionStat);
                    }
                }
            }
        }

        // update threads list
        let taskDir = match fs::read_dir(format!("/proc/{}/task", self.realPid)) {
            Ok(dir) => dir,
            Err(err) => return Err(ProcessError::IO_ERROR(err)),
        };

        for threadDir in taskDir {
            let threadDir = threadDir.unwrap();

            if threadDir.file_type().unwrap().is_dir() {
                if let Ok(realTid) = Tid::try_from(threadDir.file_name().to_str().unwrap()) {
                    // get tid
                    let threadStatusFileContent = match fs::read_to_string(format!(
                        "{}/status",
                        threadDir.path().to_str().unwrap()
                    )) {
                        Ok(content) => content,
                        Err(_) => continue,
                    };

                    let threadLines: Vec<&str> = threadStatusFileContent.lines().collect();

                    // get tid
                    let tid = if globalConfig.IsOldKernel() {
                        Tid::New(0)
                    } else {
                        let tids = threadLines[13].split_whitespace().collect::<Vec<&str>>();
                        Tid::try_from(tids[tids.len() - 1]).unwrap()
                    };

                    let mut newThread = Thread::New(tid, self.pid, realTid, self.realPid);

                    if let Ok(threadStat) = newThread.GetStat(taskStatsConnection) {
                        self.stat += threadStat;

                        // add new thread
                        self.threads.push(newThread);
                    }
                }
            }
        }

        // from here can fail and still return the stats
        self.accumulatedStat = self.stat.clone();

        // update child list
        let childrenList = match fs::read_to_string(format!(
            "/proc/{}/task/{}/children",
            self.realPid, self.realPid
        )) {
            Ok(list) => list,
            Err(_) => return Ok(self.accumulatedStat.clone()),
        };

        for childRealPid in childrenList.split_terminator(" ") {
            let mut childProcess = match GetRealProcess(&Pid::try_from(childRealPid).unwrap()) {
                Ok(child) => child,
                Err(_) => return Ok(self.accumulatedStat.clone()),
            };

            // build the child thread and process list
            let childStat = match childProcess.BuildProcessTree(taskStatsConnection, networkRawStat)
            {
                Ok(stat) => stat,
                Err(_) => return Ok(self.accumulatedStat.clone()),
            };

            self.accumulatedChildsStat += childStat;

            // add the child to this process child list
            self.childs.push(childProcess);
        }

        self.accumulatedStat = self.stat.clone() + self.accumulatedChildsStat.clone();

        Ok(self.accumulatedStat.clone())
    }
}

#[derive(Debug, Clone, Copy)]
struct UidMapEntry {
    uidStart: Uid,
    uidEnd: Uid,
    realUidStart: Uid,
    realUidEnd: Uid,
    length: usize,
}

impl UidMapEntry {
    pub fn New(uidStart: Uid, realUidStart: Uid, length: usize) -> Self {
        Self {
            uidStart,
            uidEnd: Uid::new(uidStart.to_usize() + length),
            realUidStart,
            realUidEnd: Uid::new(realUidStart.to_usize() + length),
            length,
        }
    }

    pub fn MapToUid(&self, realUid: Uid) -> Option<Uid> {
        if realUid >= self.realUidStart && realUid <= self.realUidEnd {
            Some(Uid::new(
                self.uidStart.to_usize() + realUid.to_usize() - self.realUidStart.to_usize(),
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
            return Err(ProcessError::UID_MAP_ERROR);
        }

        let start = Uid::new(values[0]);
        let realStart = Uid::new(values[1]);
        let length = values[2];

        // check length
        if length <= 0 {
            return Err(ProcessError::UID_MAP_ERROR);
        }

        Ok(Self::New(start, realStart, length))
    }
}

#[derive(Debug, Clone)]
struct UidMap {
    uidMapEntries: Vec<UidMapEntry>,
}

impl UidMap {
    pub fn New() -> Self {
        Self {
            uidMapEntries: Vec::new(),
        }
    }

    pub fn MapToUid(&self, realUid: Uid) -> Option<Uid> {
        for uidMapEntry in &self.uidMapEntries {
            if let Some(uid) = uidMapEntry.MapToUid(realUid) {
                return Some(uid);
            }
        }

        None
    }
}

impl TryFrom<&str> for UidMap {
    type Error = ProcessError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut result = Self::New();

        for line in value.lines() {
            let newUidMapEntry = UidMapEntry::try_from(line)?;

            // check for overlapping
            for uidMapEntry in &result.uidMapEntries {
                // if overlap, error
                if newUidMapEntry.uidStart >= uidMapEntry.uidStart
                    && newUidMapEntry.uidStart <= uidMapEntry.uidEnd
                {
                    return Err(ProcessError::UID_MAP_ERROR);
                }

                if newUidMapEntry.uidEnd >= uidMapEntry.uidStart
                    && newUidMapEntry.uidEnd <= uidMapEntry.uidEnd
                {
                    return Err(ProcessError::UID_MAP_ERROR);
                }
            }

            // check done
            result.uidMapEntries.push(newUidMapEntry);
        }

        Ok(result)
    }
}

#[derive(Debug, Clone, Copy)]
struct GidMapEntry {
    gidStart: Gid,
    gidEnd: Gid,
    realGidStart: Gid,
    realGidEnd: Gid,
    length: usize,
}

impl GidMapEntry {
    pub fn New(gidStart: Gid, realGidStart: Gid, length: usize) -> Self {
        Self {
            gidStart,
            gidEnd: Gid::new(gidStart.to_usize() + length),
            realGidStart,
            realGidEnd: Gid::new(realGidStart.to_usize() + length),
            length,
        }
    }

    pub fn MapToGid(&self, realGid: Gid) -> Option<Gid> {
        if realGid >= self.realGidStart && realGid <= self.realGidEnd {
            Some(Gid::new(
                self.gidStart.to_usize() + realGid.to_usize() - self.realGidStart.to_usize(),
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
            return Err(ProcessError::GID_MAP_ERROR);
        }

        let start = Gid::new(values[0]);
        let realStart = Gid::new(values[1]);
        let length = values[2];

        // check length
        if length <= 0 {
            return Err(ProcessError::GID_MAP_ERROR);
        }

        Ok(Self::New(start, realStart, length))
    }
}

#[derive(Debug, Clone)]
struct GidMap {
    gidMapEntries: Vec<GidMapEntry>,
}

impl GidMap {
    pub fn New() -> Self {
        Self {
            gidMapEntries: Vec::new(),
        }
    }

    pub fn MapToGid(&self, realGid: Gid) -> Option<Gid> {
        for gidMapEntry in &self.gidMapEntries {
            if let Some(gid) = gidMapEntry.MapToGid(realGid) {
                return Some(gid);
            }
        }

        None
    }
}

impl TryFrom<&str> for GidMap {
    type Error = ProcessError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut result = Self::New();

        for line in value.lines() {
            let newGidMapEntry = GidMapEntry::try_from(line)?;

            // check for overlapping
            for gidMapEntry in &result.gidMapEntries {
                // if overlap, error
                if newGidMapEntry.gidStart >= gidMapEntry.gidStart
                    && newGidMapEntry.gidStart <= gidMapEntry.gidEnd
                {
                    return Err(ProcessError::GID_MAP_ERROR);
                }

                if newGidMapEntry.gidEnd >= gidMapEntry.gidStart
                    && newGidMapEntry.gidEnd <= gidMapEntry.gidEnd
                {
                    return Err(ProcessError::GID_MAP_ERROR);
                }
            }

            // check done
            result.gidMapEntries.push(newGidMapEntry);
        }

        Ok(result)
    }
}

/// Make a process from realPid, with all data pulled from running system
pub fn GetRealProcess(realPid: &Pid) -> Result<Process, ProcessError> {
    let statusFileContent = fs::read_to_string(format!("/proc/{}/status", realPid))?;
    let lines: Vec<&str> = statusFileContent.lines().collect();

    // get global config
    let globalConfig = config::GetGlobalConfig().unwrap();

    // get pid
    let pid = if globalConfig.IsOldKernel() {
        Pid::New(0)
    } else {
        let pids = lines[12].split_whitespace().collect::<Vec<&str>>();
        Pid::try_from(pids[pids.len() - 1]).unwrap()
    };

    // get realParentPid
    let realParentPid = if *realPid == Pid::New(1) {
        Pid::New(0)
    } else {
        Pid::try_from(lines[6].split_whitespace().collect::<Vec<&str>>()[1])?
    };

    // get parentPid
    let parentPid = if globalConfig.IsOldKernel() {
        Pid::New(0)
    } else if *realPid == Pid::New(1) {
        Pid::New(0)
    } else {
        let parentStatusFileContent =
            fs::read_to_string(format!("/proc/{}/status", realParentPid))?;

        let parentLines: Vec<&str> = parentStatusFileContent.lines().collect();
        let parentPids = parentLines[12].split_whitespace().collect::<Vec<&str>>();

        if pid != Pid::New(1) {
            Pid::try_from(parentPids[parentPids.len() - 1])?
        } else {
            Pid::New(0)
        }
    };

    // get real uids and gids
    let realUids = lines[8].split_whitespace().collect::<Vec<&str>>();
    let realGids = lines[9].split_whitespace().collect::<Vec<&str>>();

    let realUid = Uid::try_from(realUids[1]).unwrap();
    let realEffectiveUid = Uid::try_from(realUids[2]).unwrap();
    let realSavedUid = Uid::try_from(realUids[3]).unwrap();
    let realFsUid = Uid::try_from(realUids[4]).unwrap();

    let realGid = Gid::try_from(realGids[1]).unwrap();
    let realEffectiveGid = Gid::try_from(realGids[2]).unwrap();
    let realSavedGid = Gid::try_from(realGids[3]).unwrap();
    let realFsGid = Gid::try_from(realGids[4]).unwrap();

    // map real uids and real gids to uids and gids
    let uidMap =
        UidMap::try_from(fs::read_to_string(format!("/proc/{}/uid_map", realPid))?.as_str())?;
    let gidMap =
        GidMap::try_from(fs::read_to_string(format!("/proc/{}/gid_map", realPid))?.as_str())?;

    // map every real id to id
    let uid = uidMap.MapToUid(realUid).unwrap();
    let effectiveUid = uidMap.MapToUid(realEffectiveUid).unwrap();
    let savedUid = uidMap.MapToUid(realSavedUid).unwrap();
    let fsUid = uidMap.MapToUid(realFsUid).unwrap();

    let gid = gidMap.MapToGid(realGid).unwrap();
    let effectiveGid = gidMap.MapToGid(realEffectiveGid).unwrap();
    let savedGid = gidMap.MapToGid(realSavedGid).unwrap();
    let fsGid = gidMap.MapToGid(realFsGid).unwrap();

    // get execution path
    let executionPath = fs::read_link(format!("/proc/{}/exe", realPid))?;
    let executionPath = executionPath.as_path().to_str().unwrap().to_string();

    // get command
    let command = fs::read_to_string(format!("/proc/{}/comm", realPid))?;

    Ok(Process::New(
        pid,
        parentPid,
        uid,
        effectiveUid,
        savedUid,
        fsUid,
        gid,
        effectiveGid,
        savedGid,
        fsGid,
        *realPid,
        realParentPid,
        realUid,
        realEffectiveUid,
        realSavedUid,
        realFsUid,
        realGid,
        realEffectiveGid,
        realSavedGid,
        realFsGid,
        executionPath,
        command,
    ))
}

#[derive(Debug)]
pub enum ProcessError {
    IO_ERROR(io::Error),
    TASKSTATS_ERROR(TaskStatsError),
    PARSE_INT_ERROR(std::num::ParseIntError),
    UID_MAP_ERROR,
    GID_MAP_ERROR,
    COMMON_ERROR(CommonError),
}

impl std::error::Error for ProcessError {}

impl fmt::Display for ProcessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let result = match self {
            Self::IO_ERROR(error) => String::from(format!("IO error: {}", error)),
            Self::TASKSTATS_ERROR(error) => String::from(format!("Taskstats error: {}", error)),
            Self::PARSE_INT_ERROR(error) => String::from(format!("Parse integer error: {}", error)),
            Self::UID_MAP_ERROR => String::from(format!("Uid map error")),
            Self::GID_MAP_ERROR => String::from(format!("Gid map error")),
            Self::COMMON_ERROR(error) => String::from(format!("Common error: {}", error)),
        };

        write!(f, "{}", result)
    }
}

impl From<TaskStatsError> for ProcessError {
    fn from(error: TaskStatsError) -> Self {
        Self::TASKSTATS_ERROR(error)
    }
}

impl From<io::Error> for ProcessError {
    fn from(error: io::Error) -> Self {
        Self::IO_ERROR(error)
    }
}

impl From<std::num::ParseIntError> for ProcessError {
    fn from(error: std::num::ParseIntError) -> Self {
        Self::PARSE_INT_ERROR(error)
    }
}

impl From<CommonError> for ProcessError {
    fn from(error: CommonError) -> Self {
        Self::COMMON_ERROR(error)
    }
}
