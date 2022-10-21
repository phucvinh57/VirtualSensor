use std::convert::{TryFrom, TryInto};
use std::error::Error;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{fmt, mem, slice};

use crate::common::{Count, DataCount, Gid, TimeCount, Timestamp, Uid};
use crate::netlink::generic::{GenericError, GenericNetlinkConnection};
use crate::netlink::generic::{GenericNetlinkControlMessage, GenericNetlinkControlMessageCommand};
use crate::netlink::generic::{
    GenericNetlinkControlMessageAttribute, GenericNetlinkControlMessageAttributeType,
};
use crate::netlink::generic::{
    GenericNetlinkMessage, GenericNetlinkMessageCommand, GenericNetlinkMessageType,
};
use crate::netlink::generic::{GenericNetlinkMessageAttribute, GenericNetlinkMessageAttributeType};
use crate::Process::{Pid, Tid};

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct TaskStatsRawV8 {
    version: u16,
    padding1: [u8; 2],
    exitcode: u32,
    flags: u8,
    nice: i8,
    padding2: [u8; 6],

    // delay accounting fields
    cpuDelayCount: u64,
    cpuDelayTotal: u64, // in nanoseconds

    blockIODelayCount: u64,
    blockIODelayTotal: u64, // in nanoseconds

    swapinDelayCount: u64,
    swapinDelayTotal: u64, // in nanoseconds

    cpuRuntimeRealTotal: u64,    // in nanoseconds
    cpuRuntimeVirtualTotal: u64, // in nanoseconds

    // basic fields
    commandString: [u8; Self::COMMAND_LENGTH],
    schedulingDiscipline: u8,
    padding3: [u8; 3],
    padding4: [u8; 4],

    uid: u32,
    gid: u32,
    pid: u32,
    parentPid: u32,

    beginTime: u32, // in seconds
    padding5: [u8; 4],
    elapsedTime: u64, // in microseconds

    userCpuTime: u64,   // in microseconds
    systemCpuTime: u64, // in microseconds

    minorFaultCount: u64,
    majorFaultCount: u64,

    // extended accounting fields
    accumulatedRss: u64, // in MB
    accumulatedVss: u64, // in MB

    highWaterRss: u64, // in KB
    highWaterVss: u64, // in KB

    ioReadBytes: u64,
    ioWriteBytes: u64,

    readSyscallCount: u64,
    writeSyscallCount: u64,

    // storage IO accounting fields
    blockIOReadBytes: u64,
    blockIOWriteBytes: u64,
    cancelledBlockIOWriteBytes: u64,

    voluntaryContextSwitches: u64,
    nonvoluntaryContextSwitches: u64,

    userTimeScaled: u64,
    systemTimeScaled: u64,
    runRealTotalScaled: u64,

    freePagesDelayCount: u64,
    freePagesDelayTotal: u64,
}

impl TaskStatsRawV8 {
    const LENGTH: usize = mem::size_of::<TaskStatsRawV8>();
    const VERSION: u16 = 8;
    const COMMAND_LENGTH: usize = 32;

    pub fn ToByteArray(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(unsafe {
            slice::from_raw_parts(self as *const _ as *const u8, Self::LENGTH)
        });
        result
    }

    pub fn FromByteArray(buf: &[u8]) -> Result<Self, TaskStatsError> {
        // check version
        let version = unsafe { *(buf as *const _ as *const u16) };
        if version != Self::VERSION {
            return Err(TaskStatsError::UNSUPPORTED_TASKSTATS_VERSION(version));
        }

        // check size
        if buf.len() < Self::LENGTH {
            return Err(TaskStatsError::TASK_STRUCT_ERROR(buf.to_vec()));
        }

        Ok(unsafe { *(buf as *const _ as *mut Self) })
    }

    pub fn CommandString(&self) -> String {
        std::str::from_utf8(&self.commandString)
            .unwrap()
            .to_string()
    }

    pub fn ToTaskStats(&self) -> TaskStats {
        TaskStats {
            commandString: self.CommandString(),
            pid: Pid::New(self.pid as usize),
            uid: Uid::New(self.uid as usize),
            gid: Gid::New(self.gid as usize),
            parentPid: Pid::New(self.parentPid as usize),
            nice: self.nice as isize,
            flags: self.flags as usize,
            exitcode: self.exitcode as usize,
            timestamp: Timestamp::GetCurrentTimestamp(),

            beginTime: UNIX_EPOCH + Duration::from_secs(self.beginTime as u64),
            elapsedTime: TimeCount::FromMicroSeconds(self.elapsedTime.try_into().unwrap()),
            schedulingDiscipline: self.schedulingDiscipline,

            userCpuTime: TimeCount::FromMicroSeconds(self.userCpuTime.try_into().unwrap()),
            systemCpuTime: TimeCount::FromMicroSeconds(self.systemCpuTime.try_into().unwrap()),

            accumulatedRss: DataCount::FromMB(self.accumulatedRss.try_into().unwrap()),
            accumulatedVss: DataCount::FromMB(self.accumulatedVss.try_into().unwrap()),

            highWaterRss: DataCount::FromKB(self.highWaterRss.try_into().unwrap()),
            highWaterVss: DataCount::FromKB(self.highWaterVss.try_into().unwrap()),

            ioRead: DataCount::FromByte(self.ioReadBytes.try_into().unwrap()),
            ioWrite: DataCount::FromByte(self.ioWriteBytes.try_into().unwrap()),

            readSyscallCount: Count::New(self.readSyscallCount.try_into().unwrap()),
            writeSyscallCount: Count::New(self.writeSyscallCount.try_into().unwrap()),

            blockIORead: DataCount::FromByte(self.blockIOReadBytes.try_into().unwrap()),
            blockIOWrite: DataCount::FromByte(self.blockIOWriteBytes.try_into().unwrap()),
            cancelledBlockIOWrite: DataCount::FromByte(
                self.cancelledBlockIOWriteBytes.try_into().unwrap(),
            ),

            cpuDelayCount: Count::New(self.cpuDelayCount.try_into().unwrap()),
            cpuDelayTotal: TimeCount::FromNanoSeconds(self.cpuDelayTotal.try_into().unwrap()),

            minorFaultCount: Count::New(self.minorFaultCount.try_into().unwrap()),
            majorFaultCount: Count::New(self.majorFaultCount.try_into().unwrap()),

            freePagesDelayCount: Count::New(self.freePagesDelayCount.try_into().unwrap()),
            freePagesDelayTotal: TimeCount::FromNanoSeconds(
                self.freePagesDelayTotal.try_into().unwrap(),
            ),

            thrashingDelayCount: Count::New(0),
            thrashingDelayTotal: TimeCount::FromNanoSeconds(0),

            blockIODelayCount: Count::New(self.blockIODelayCount.try_into().unwrap()),
            blockIODelayTotal: TimeCount::FromNanoSeconds(
                self.blockIODelayTotal.try_into().unwrap(),
            ),

            swapinDelayCount: Count::New(self.swapinDelayCount.try_into().unwrap()),
            swapinDelayTotal: TimeCount::FromNanoSeconds(self.swapinDelayTotal.try_into().unwrap()),

            memoryCompactDelayCount: Count::New(0),
            memoryCompactDelayTotal: TimeCount::FromNanoSeconds(0),

            voluntaryContextSwitches: Count::New(self.voluntaryContextSwitches.try_into().unwrap()),
            nonvoluntaryContextSwitches: Count::New(
                self.nonvoluntaryContextSwitches.try_into().unwrap(),
            ),

            cpuRuntimeRealTotal: TimeCount::FromNanoSeconds(
                self.cpuRuntimeRealTotal.try_into().unwrap(),
            ),
            cpuRuntimeVirtualTotal: TimeCount::FromNanoSeconds(
                self.cpuRuntimeVirtualTotal.try_into().unwrap(),
            ),

            userTimeScaled: TimeCount::FromNanoSeconds(self.userTimeScaled.try_into().unwrap()),
            systemTimeScaled: TimeCount::FromNanoSeconds(self.systemTimeScaled.try_into().unwrap()),
            runRealTotalScaled: TimeCount::FromNanoSeconds(
                self.runRealTotalScaled.try_into().unwrap(),
            ),
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct TaskStatsRawV9 {
    version: u16,
    padding1: [u8; 2],
    exitcode: u32,
    flags: u8,
    nice: i8,
    padding2: [u8; 6],

    // delay accounting fields
    cpuDelayCount: u64,
    cpuDelayTotal: u64, // in nanoseconds

    blockIODelayCount: u64,
    blockIODelayTotal: u64, // in nanoseconds

    swapinDelayCount: u64,
    swapinDelayTotal: u64, // in nanoseconds

    cpuRuntimeRealTotal: u64,    // in nanoseconds
    cpuRuntimeVirtualTotal: u64, // in nanoseconds

    // basic fields
    commandString: [u8; Self::COMMAND_LENGTH],
    schedulingDiscipline: u8,
    padding3: [u8; 3],
    padding4: [u8; 4],

    uid: u32,
    gid: u32,
    pid: u32,
    parentPid: u32,

    beginTime: u32, // in seconds
    padding5: [u8; 4],
    elapsedTime: u64, // in microseconds

    userCpuTime: u64,   // in microseconds
    systemCpuTime: u64, // in microseconds

    minorFaultCount: u64,
    majorFaultCount: u64,

    // extended accounting fields
    accumulatedRss: u64, // in MB
    accumulatedVss: u64, // in MB

    highWaterRss: u64, // in KB
    highWaterVss: u64, // in KB

    ioReadBytes: u64,
    ioWriteBytes: u64,

    readSyscallCount: u64,
    writeSyscallCount: u64,

    // storage IO accounting fields
    blockIOReadBytes: u64,
    blockIOWriteBytes: u64,
    cancelledBlockIOWriteBytes: u64,

    voluntaryContextSwitches: u64,
    nonvoluntaryContextSwitches: u64,

    userTimeScaled: u64,
    systemTimeScaled: u64,
    runRealTotalScaled: u64,

    freePagesDelayCount: u64,
    freePagesDelayTotal: u64,

    thrashingDelayCount: u64,
    thrashingDelayTotal: u64,
}

impl TaskStatsRawV9 {
    const LENGTH: usize = mem::size_of::<TaskStatsRawV9>();
    const VERSION: u16 = 9;
    const COMMAND_LENGTH: usize = 32;

    pub fn ToByteArray(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(unsafe {
            slice::from_raw_parts(self as *const _ as *const u8, Self::LENGTH)
        });
        result
    }

    pub fn FromByteArray(buf: &[u8]) -> Result<Self, TaskStatsError> {
        // check version
        let version = unsafe { *(buf as *const _ as *const u16) };
        if version != Self::VERSION {
            return Err(TaskStatsError::UNSUPPORTED_TASKSTATS_VERSION(version));
        }

        // check size
        if buf.len() < Self::LENGTH {
            return Err(TaskStatsError::TASK_STRUCT_ERROR(buf.to_vec()));
        }

        Ok(unsafe { *(buf as *const _ as *mut Self) })
    }

    pub fn CommandString(&self) -> String {
        std::str::from_utf8(&self.commandString)
            .unwrap()
            .to_string()
    }

    pub fn ToTaskStats(&self) -> TaskStats {
        TaskStats {
            commandString: self.CommandString(),
            pid: Pid::New(self.pid as usize),
            uid: Uid::New(self.uid as usize),
            gid: Gid::New(self.gid as usize),
            parentPid: Pid::New(self.parentPid as usize),
            nice: self.nice as isize,
            flags: self.flags as usize,
            exitcode: self.exitcode as usize,
            timestamp: Timestamp::GetCurrentTimestamp(),

            beginTime: UNIX_EPOCH + Duration::from_secs(self.beginTime as u64),
            elapsedTime: TimeCount::FromMicroSeconds(self.elapsedTime.try_into().unwrap()),
            schedulingDiscipline: self.schedulingDiscipline,

            userCpuTime: TimeCount::FromMicroSeconds(self.userCpuTime.try_into().unwrap()),
            systemCpuTime: TimeCount::FromMicroSeconds(self.systemCpuTime.try_into().unwrap()),

            accumulatedRss: DataCount::FromMB(self.accumulatedRss.try_into().unwrap()),
            accumulatedVss: DataCount::FromMB(self.accumulatedVss.try_into().unwrap()),

            highWaterRss: DataCount::FromKB(self.highWaterRss.try_into().unwrap()),
            highWaterVss: DataCount::FromKB(self.highWaterVss.try_into().unwrap()),

            ioRead: DataCount::FromByte(self.ioReadBytes.try_into().unwrap()),
            ioWrite: DataCount::FromByte(self.ioWriteBytes.try_into().unwrap()),

            readSyscallCount: Count::New(self.readSyscallCount.try_into().unwrap()),
            writeSyscallCount: Count::New(self.writeSyscallCount.try_into().unwrap()),

            blockIORead: DataCount::FromByte(self.blockIOReadBytes.try_into().unwrap()),
            blockIOWrite: DataCount::FromByte(self.blockIOWriteBytes.try_into().unwrap()),
            cancelledBlockIOWrite: DataCount::FromByte(
                self.cancelledBlockIOWriteBytes.try_into().unwrap(),
            ),

            cpuDelayCount: Count::New(self.cpuDelayCount.try_into().unwrap()),
            cpuDelayTotal: TimeCount::FromNanoSeconds(self.cpuDelayTotal.try_into().unwrap()),

            minorFaultCount: Count::New(self.minorFaultCount.try_into().unwrap()),
            majorFaultCount: Count::New(self.majorFaultCount.try_into().unwrap()),

            freePagesDelayCount: Count::New(self.freePagesDelayCount.try_into().unwrap()),
            freePagesDelayTotal: TimeCount::FromNanoSeconds(
                self.freePagesDelayTotal.try_into().unwrap(),
            ),

            thrashingDelayCount: Count::New(self.thrashingDelayCount.try_into().unwrap()),
            thrashingDelayTotal: TimeCount::FromNanoSeconds(
                self.thrashingDelayTotal.try_into().unwrap(),
            ),

            blockIODelayCount: Count::New(self.blockIODelayCount.try_into().unwrap()),
            blockIODelayTotal: TimeCount::FromNanoSeconds(
                self.blockIODelayTotal.try_into().unwrap(),
            ),

            swapinDelayCount: Count::New(self.swapinDelayCount.try_into().unwrap()),
            swapinDelayTotal: TimeCount::FromNanoSeconds(self.swapinDelayTotal.try_into().unwrap()),

            memoryCompactDelayCount: Count::New(0),
            memoryCompactDelayTotal: TimeCount::FromNanoSeconds(0),

            voluntaryContextSwitches: Count::New(self.voluntaryContextSwitches.try_into().unwrap()),
            nonvoluntaryContextSwitches: Count::New(
                self.nonvoluntaryContextSwitches.try_into().unwrap(),
            ),

            cpuRuntimeRealTotal: TimeCount::FromNanoSeconds(
                self.cpuRuntimeRealTotal.try_into().unwrap(),
            ),
            cpuRuntimeVirtualTotal: TimeCount::FromNanoSeconds(
                self.cpuRuntimeVirtualTotal.try_into().unwrap(),
            ),

            userTimeScaled: TimeCount::FromNanoSeconds(self.userTimeScaled.try_into().unwrap()),
            systemTimeScaled: TimeCount::FromNanoSeconds(self.systemTimeScaled.try_into().unwrap()),
            runRealTotalScaled: TimeCount::FromNanoSeconds(
                self.runRealTotalScaled.try_into().unwrap(),
            ),
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct TaskStatsRawV10 {
    version: u16,
    padding1: [u8; 2],
    exitcode: u32,
    flags: u8,
    nice: i8,
    padding2: [u8; 6],

    // delay accounting fields
    cpuDelayCount: u64,
    cpuDelayTotal: u64, // in nanoseconds

    blockIODelayCount: u64,
    blockIODelayTotal: u64, // in nanoseconds

    swapinDelayCount: u64,
    swapinDelayTotal: u64, // in nanoseconds

    cpuRuntimeRealTotal: u64,    // in nanoseconds
    cpuRuntimeVirtualTotal: u64, // in nanoseconds

    // basic fields
    commandString: [u8; Self::COMMAND_LENGTH],
    schedulingDiscipline: u8,
    padding3: [u8; 3],
    padding4: [u8; 4],

    uid: u32,
    gid: u32,
    pid: u32,
    parentPid: u32,

    beginTime: u32, // in seconds
    padding5: [u8; 4],
    elapsedTime: u64, // in microseconds

    userCpuTime: u64,   // in microseconds
    systemCpuTime: u64, // in microseconds

    minorFaultCount: u64,
    majorFaultCount: u64,

    // extended accounting fields
    accumulatedRss: u64, // in MB
    accumulatedVss: u64, // in MB

    highWaterRss: u64, // in KB
    highWaterVss: u64, // in KB

    ioReadBytes: u64,
    ioWriteBytes: u64,

    readSyscallCount: u64,
    writeSyscallCount: u64,

    // storage IO accounting fields
    blockIOReadBytes: u64,
    blockIOWriteBytes: u64,
    cancelledBlockIOWriteBytes: u64,

    voluntaryContextSwitches: u64,
    nonvoluntaryContextSwitches: u64,

    userTimeScaled: u64,
    systemTimeScaled: u64,
    runRealTotalScaled: u64,

    freePagesDelayCount: u64,
    freePagesDelayTotal: u64,

    thrashingDelayCount: u64,
    thrashingDelayTotal: u64,

    beginTime64: u64,
}

impl TaskStatsRawV10 {
    const LENGTH: usize = mem::size_of::<TaskStatsRawV10>();
    const VERSION: u16 = 10;
    const COMMAND_LENGTH: usize = 32;

    pub fn ToByteArray(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(unsafe {
            slice::from_raw_parts(self as *const _ as *const u8, Self::LENGTH)
        });
        result
    }

    pub fn FromByteArray(buf: &[u8]) -> Result<Self, TaskStatsError> {
        // check version
        let version = unsafe { *(buf as *const _ as *const u16) };
        if version != Self::VERSION {
            return Err(TaskStatsError::UNSUPPORTED_TASKSTATS_VERSION(version));
        }

        // check size
        if buf.len() < Self::LENGTH {
            return Err(TaskStatsError::TASK_STRUCT_ERROR(buf.to_vec()));
        }

        Ok(unsafe { *(buf as *const _ as *mut Self) })
    }

    pub fn CommandString(&self) -> String {
        std::str::from_utf8(&self.commandString)
            .unwrap()
            .to_string()
    }

    pub fn ToTaskStats(&self) -> TaskStats {
        TaskStats {
            commandString: self.CommandString(),
            pid: Pid::New(self.pid as usize),
            uid: Uid::New(self.uid as usize),
            gid: Gid::New(self.gid as usize),
            parentPid: Pid::New(self.parentPid as usize),
            nice: self.nice as isize,
            flags: self.flags as usize,
            exitcode: self.exitcode as usize,
            timestamp: Timestamp::GetCurrentTimestamp(),

            beginTime: UNIX_EPOCH + Duration::from_secs(self.beginTime as u64),
            elapsedTime: TimeCount::FromMicroSeconds(self.elapsedTime.try_into().unwrap()),
            schedulingDiscipline: self.schedulingDiscipline,

            userCpuTime: TimeCount::FromMicroSeconds(self.userCpuTime.try_into().unwrap()),
            systemCpuTime: TimeCount::FromMicroSeconds(self.systemCpuTime.try_into().unwrap()),

            accumulatedRss: DataCount::FromMB(self.accumulatedRss.try_into().unwrap()),
            accumulatedVss: DataCount::FromMB(self.accumulatedVss.try_into().unwrap()),

            highWaterRss: DataCount::FromKB(self.highWaterRss.try_into().unwrap()),
            highWaterVss: DataCount::FromKB(self.highWaterVss.try_into().unwrap()),

            ioRead: DataCount::FromByte(self.ioReadBytes.try_into().unwrap()),
            ioWrite: DataCount::FromByte(self.ioWriteBytes.try_into().unwrap()),

            readSyscallCount: Count::New(self.readSyscallCount.try_into().unwrap()),
            writeSyscallCount: Count::New(self.writeSyscallCount.try_into().unwrap()),

            blockIORead: DataCount::FromByte(self.blockIOReadBytes.try_into().unwrap()),
            blockIOWrite: DataCount::FromByte(self.blockIOWriteBytes.try_into().unwrap()),
            cancelledBlockIOWrite: DataCount::FromByte(
                self.cancelledBlockIOWriteBytes.try_into().unwrap(),
            ),

            cpuDelayCount: Count::New(self.cpuDelayCount.try_into().unwrap()),
            cpuDelayTotal: TimeCount::FromNanoSeconds(self.cpuDelayTotal.try_into().unwrap()),

            minorFaultCount: Count::New(self.minorFaultCount.try_into().unwrap()),
            majorFaultCount: Count::New(self.majorFaultCount.try_into().unwrap()),

            freePagesDelayCount: Count::New(self.freePagesDelayCount.try_into().unwrap()),
            freePagesDelayTotal: TimeCount::FromNanoSeconds(
                self.freePagesDelayTotal.try_into().unwrap(),
            ),

            thrashingDelayCount: Count::New(self.thrashingDelayCount.try_into().unwrap()),
            thrashingDelayTotal: TimeCount::FromNanoSeconds(
                self.thrashingDelayTotal.try_into().unwrap(),
            ),

            blockIODelayCount: Count::New(self.blockIODelayCount.try_into().unwrap()),
            blockIODelayTotal: TimeCount::FromNanoSeconds(
                self.blockIODelayTotal.try_into().unwrap(),
            ),

            swapinDelayCount: Count::New(self.swapinDelayCount.try_into().unwrap()),
            swapinDelayTotal: TimeCount::FromNanoSeconds(self.swapinDelayTotal.try_into().unwrap()),

            memoryCompactDelayCount: Count::New(0),
            memoryCompactDelayTotal: TimeCount::FromNanoSeconds(0),

            voluntaryContextSwitches: Count::New(self.voluntaryContextSwitches.try_into().unwrap()),
            nonvoluntaryContextSwitches: Count::New(
                self.nonvoluntaryContextSwitches.try_into().unwrap(),
            ),

            cpuRuntimeRealTotal: TimeCount::FromNanoSeconds(
                self.cpuRuntimeRealTotal.try_into().unwrap(),
            ),
            cpuRuntimeVirtualTotal: TimeCount::FromNanoSeconds(
                self.cpuRuntimeVirtualTotal.try_into().unwrap(),
            ),

            userTimeScaled: TimeCount::FromNanoSeconds(self.userTimeScaled.try_into().unwrap()),
            systemTimeScaled: TimeCount::FromNanoSeconds(self.systemTimeScaled.try_into().unwrap()),
            runRealTotalScaled: TimeCount::FromNanoSeconds(
                self.runRealTotalScaled.try_into().unwrap(),
            ),
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct TaskStatsRawV11 {
    version: u16,
    padding1: [u8; 2],
    exitcode: u32,
    flags: u8,
    nice: i8,
    padding2: [u8; 6],

    // delay accounting fields
    cpuDelayCount: u64,
    cpuDelayTotal: u64, // in nanoseconds

    blockIODelayCount: u64,
    blockIODelayTotal: u64, // in nanoseconds

    swapinDelayCount: u64,
    swapinDelayTotal: u64, // in nanoseconds

    cpuRuntimeRealTotal: u64,    // in nanoseconds
    cpuRuntimeVirtualTotal: u64, // in nanoseconds

    // basic fields
    commandString: [u8; Self::COMMAND_LENGTH],
    schedulingDiscipline: u8,
    padding3: [u8; 3],
    padding4: [u8; 4],

    uid: u32,
    gid: u32,
    pid: u32,
    parentPid: u32,

    beginTime: u32, // in seconds
    padding5: [u8; 4],
    elapsedTime: u64, // in microseconds

    userCpuTime: u64,   // in microseconds
    systemCpuTime: u64, // in microseconds

    minorFaultCount: u64,
    majorFaultCount: u64,

    // extended accounting fields
    accumulatedRss: u64, // in MB
    accumulatedVss: u64, // in MB

    highWaterRss: u64, // in KB
    highWaterVss: u64, // in KB

    ioReadBytes: u64,
    ioWriteBytes: u64,

    readSyscallCount: u64,
    writeSyscallCount: u64,

    // storage IO accounting fields
    blockIOReadBytes: u64,
    blockIOWriteBytes: u64,
    cancelledBlockIOWriteBytes: u64,

    voluntaryContextSwitches: u64,
    nonvoluntaryContextSwitches: u64,

    userTimeScaled: u64,
    systemTimeScaled: u64,
    runRealTotalScaled: u64,

    freePagesDelayCount: u64,
    freePagesDelayTotal: u64,

    thrashingDelayCount: u64,
    thrashingDelayTotal: u64,

    beginTime64: u64,

    memoryCompactDelayCount: u64,
    memoryCompactDelayTotal: u64,
}

impl TaskStatsRawV11 {
    const LENGTH: usize = mem::size_of::<TaskStatsRawV11>();
    const VERSION: u16 = 11;
    const COMMAND_LENGTH: usize = 32;

    pub fn ToByteArray(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(unsafe {
            slice::from_raw_parts(self as *const _ as *const u8, Self::LENGTH)
        });
        result
    }

    pub fn FromByteArray(buf: &[u8]) -> Result<Self, TaskStatsError> {
        // check version
        let version = unsafe { *(buf as *const _ as *const u16) };
        if version != Self::VERSION {
            return Err(TaskStatsError::UNSUPPORTED_TASKSTATS_VERSION(version));
        }

        // check size
        if buf.len() < Self::LENGTH {
            return Err(TaskStatsError::TASK_STRUCT_ERROR(buf.to_vec()));
        }

        Ok(unsafe { *(buf as *const _ as *mut Self) })
    }

    pub fn CommandString(&self) -> String {
        std::str::from_utf8(&self.commandString)
            .unwrap()
            .to_string()
    }

    pub fn ToTaskStats(&self) -> TaskStats {
        TaskStats {
            commandString: self.CommandString(),
            pid: Pid::New(self.pid as usize),
            uid: Uid::New(self.uid as usize),
            gid: Gid::New(self.gid as usize),
            parentPid: Pid::New(self.parentPid as usize),
            nice: self.nice as isize,
            flags: self.flags as usize,
            exitcode: self.exitcode as usize,
            timestamp: Timestamp::GetCurrentTimestamp(),

            beginTime: UNIX_EPOCH + Duration::from_secs(self.beginTime as u64),
            elapsedTime: TimeCount::FromMicroSeconds(self.elapsedTime.try_into().unwrap()),
            schedulingDiscipline: self.schedulingDiscipline,

            userCpuTime: TimeCount::FromMicroSeconds(self.userCpuTime.try_into().unwrap()),
            systemCpuTime: TimeCount::FromMicroSeconds(self.systemCpuTime.try_into().unwrap()),

            accumulatedRss: DataCount::FromMB(self.accumulatedRss.try_into().unwrap()),
            accumulatedVss: DataCount::FromMB(self.accumulatedVss.try_into().unwrap()),

            highWaterRss: DataCount::FromKB(self.highWaterRss.try_into().unwrap()),
            highWaterVss: DataCount::FromKB(self.highWaterVss.try_into().unwrap()),

            ioRead: DataCount::FromByte(self.ioReadBytes.try_into().unwrap()),
            ioWrite: DataCount::FromByte(self.ioWriteBytes.try_into().unwrap()),

            readSyscallCount: Count::New(self.readSyscallCount.try_into().unwrap()),
            writeSyscallCount: Count::New(self.writeSyscallCount.try_into().unwrap()),

            blockIORead: DataCount::FromByte(self.blockIOReadBytes.try_into().unwrap()),
            blockIOWrite: DataCount::FromByte(self.blockIOWriteBytes.try_into().unwrap()),
            cancelledBlockIOWrite: DataCount::FromByte(
                self.cancelledBlockIOWriteBytes.try_into().unwrap(),
            ),

            cpuDelayCount: Count::New(self.cpuDelayCount.try_into().unwrap()),
            cpuDelayTotal: TimeCount::FromNanoSeconds(self.cpuDelayTotal.try_into().unwrap()),

            minorFaultCount: Count::New(self.minorFaultCount.try_into().unwrap()),
            majorFaultCount: Count::New(self.majorFaultCount.try_into().unwrap()),

            freePagesDelayCount: Count::New(self.freePagesDelayCount.try_into().unwrap()),
            freePagesDelayTotal: TimeCount::FromNanoSeconds(
                self.freePagesDelayTotal.try_into().unwrap(),
            ),

            thrashingDelayCount: Count::New(self.thrashingDelayCount.try_into().unwrap()),
            thrashingDelayTotal: TimeCount::FromNanoSeconds(
                self.thrashingDelayTotal.try_into().unwrap(),
            ),

            blockIODelayCount: Count::New(self.blockIODelayCount.try_into().unwrap()),
            blockIODelayTotal: TimeCount::FromNanoSeconds(
                self.blockIODelayTotal.try_into().unwrap(),
            ),

            swapinDelayCount: Count::New(self.swapinDelayCount.try_into().unwrap()),
            swapinDelayTotal: TimeCount::FromNanoSeconds(self.swapinDelayTotal.try_into().unwrap()),

            memoryCompactDelayCount: Count::New(self.memoryCompactDelayCount.try_into().unwrap()),
            memoryCompactDelayTotal: TimeCount::FromNanoSeconds(
                self.memoryCompactDelayTotal.try_into().unwrap(),
            ),

            voluntaryContextSwitches: Count::New(self.voluntaryContextSwitches.try_into().unwrap()),
            nonvoluntaryContextSwitches: Count::New(
                self.nonvoluntaryContextSwitches.try_into().unwrap(),
            ),

            cpuRuntimeRealTotal: TimeCount::FromNanoSeconds(
                self.cpuRuntimeRealTotal.try_into().unwrap(),
            ),
            cpuRuntimeVirtualTotal: TimeCount::FromNanoSeconds(
                self.cpuRuntimeVirtualTotal.try_into().unwrap(),
            ),

            userTimeScaled: TimeCount::FromNanoSeconds(self.userTimeScaled.try_into().unwrap()),
            systemTimeScaled: TimeCount::FromNanoSeconds(self.systemTimeScaled.try_into().unwrap()),
            runRealTotalScaled: TimeCount::FromNanoSeconds(
                self.runRealTotalScaled.try_into().unwrap(),
            ),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum TaskStatsRaw {
    V8(TaskStatsRawV8),
    V9(TaskStatsRawV9),
    V10(TaskStatsRawV10),
    V11(TaskStatsRawV11),
}

impl TaskStatsRaw {
    pub fn ToByteArray(&self) -> Vec<u8> {
        match self {
            Self::V8(stats) => stats.ToByteArray(),
            Self::V9(stats) => stats.ToByteArray(),
            Self::V10(stats) => stats.ToByteArray(),
            Self::V11(stats) => stats.ToByteArray(),
        }
    }

    pub fn FromByteArray(buf: &[u8]) -> Result<Self, TaskStatsError> {
        // get version
        let version = u16::from_ne_bytes(buf[0..2].try_into().unwrap());

        match version {
            8 => Ok(Self::V8(TaskStatsRawV8::FromByteArray(buf)?)),
            9 => Ok(Self::V9(TaskStatsRawV9::FromByteArray(buf)?)),
            10 => Ok(Self::V10(TaskStatsRawV10::FromByteArray(buf)?)),
            11 => Ok(Self::V11(TaskStatsRawV11::FromByteArray(buf)?)),
            _ => Err(TaskStatsError::UNSUPPORTED_TASKSTATS_VERSION(version)),
        }
    }

    pub fn ToTaskStats(&self) -> TaskStats {
        match self {
            Self::V8(stats) => stats.ToTaskStats(),
            Self::V9(stats) => stats.ToTaskStats(),
            Self::V10(stats) => stats.ToTaskStats(),
            Self::V11(stats) => stats.ToTaskStats(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TaskStats {
    pub commandString: String,
    pub pid: Pid,
    pub uid: Uid,
    pub gid: Gid,
    pub parentPid: Pid,
    pub nice: isize,
    pub flags: usize,
    pub exitcode: usize,
    pub timestamp: Timestamp,

    pub beginTime: SystemTime,
    pub elapsedTime: TimeCount,
    pub schedulingDiscipline: u8,

    pub userCpuTime: TimeCount,
    pub systemCpuTime: TimeCount,

    pub accumulatedRss: DataCount,
    pub accumulatedVss: DataCount,

    pub highWaterRss: DataCount,
    pub highWaterVss: DataCount,

    pub ioRead: DataCount,
    pub ioWrite: DataCount,

    pub readSyscallCount: Count,
    pub writeSyscallCount: Count,

    pub blockIORead: DataCount,
    pub blockIOWrite: DataCount,
    pub cancelledBlockIOWrite: DataCount,

    pub cpuDelayCount: Count,
    pub cpuDelayTotal: TimeCount,

    pub minorFaultCount: Count,
    pub majorFaultCount: Count,

    pub freePagesDelayCount: Count,
    pub freePagesDelayTotal: TimeCount,

    pub thrashingDelayCount: Count,
    pub thrashingDelayTotal: TimeCount,

    pub blockIODelayCount: Count,
    pub blockIODelayTotal: TimeCount,

    pub swapinDelayCount: Count,
    pub swapinDelayTotal: TimeCount,

    pub memoryCompactDelayCount: Count,
    pub memoryCompactDelayTotal: TimeCount,

    pub voluntaryContextSwitches: Count,
    pub nonvoluntaryContextSwitches: Count,

    pub cpuRuntimeRealTotal: TimeCount,
    pub cpuRuntimeVirtualTotal: TimeCount,

    pub userTimeScaled: TimeCount,
    pub systemTimeScaled: TimeCount,
    pub runRealTotalScaled: TimeCount,
}

impl TaskStats {}

impl From<TaskStatsRaw> for TaskStats {
    fn from(taskStatsRaw: TaskStatsRaw) -> Self {
        taskStatsRaw.ToTaskStats()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskStatsCommand {
    UNSPECIFIED = 0, /* Reserved */
    GET = 1,         /* user->kernel request/get-response */
    NEW = 2,         /* kernel->user event */
}

impl Into<GenericNetlinkMessageCommand> for TaskStatsCommand {
    fn into(self) -> GenericNetlinkMessageCommand {
        GenericNetlinkMessageCommand::New(self as u8)
    }
}

impl TryFrom<GenericNetlinkMessageCommand> for TaskStatsCommand {
    type Error = TaskStatsError;

    fn try_from(
        genericNetlinkMessageCommand: GenericNetlinkMessageCommand,
    ) -> Result<Self, Self::Error> {
        let command = genericNetlinkMessageCommand.into();

        match command {
            x if x == Self::UNSPECIFIED as u8 => Ok(Self::UNSPECIFIED),
            x if x == Self::GET as u8 => Ok(Self::GET),
            x if x == Self::NEW as u8 => Ok(Self::NEW),
            _ => Err(TaskStatsError::UNKNOWN_COMMAND(command)),
        }
    }
}

#[derive(Debug, Clone)]
struct TaskStatsAttribute {
    attributeType: TaskStatsAttributeType,
    payload: Vec<u8>,
}

impl TaskStatsAttribute {
    pub fn New(attributeType: TaskStatsAttributeType, payload: Vec<u8>) -> Self {
        Self {
            attributeType,
            payload,
        }
    }

    pub fn Type(&self) -> TaskStatsAttributeType {
        self.attributeType
    }
}

impl Into<GenericNetlinkMessageAttribute> for TaskStatsAttribute {
    fn into(self) -> GenericNetlinkMessageAttribute {
        GenericNetlinkMessageAttribute::New(self.attributeType.into(), self.payload)
    }
}

impl From<GenericNetlinkMessageAttribute> for TaskStatsAttribute {
    fn from(genericNetlinkMessageAttribute: GenericNetlinkMessageAttribute) -> Self {
        TaskStatsAttribute::New(
            genericNetlinkMessageAttribute.Type().into(),
            genericNetlinkMessageAttribute.payload,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskStatsAttributeType(u16);

impl TaskStatsAttributeType {
    pub fn New(value: u16) -> Self {
        Self(value)
    }
}

impl Into<GenericNetlinkMessageAttributeType> for TaskStatsAttributeType {
    fn into(self) -> GenericNetlinkMessageAttributeType {
        GenericNetlinkMessageAttributeType::New(self.0)
    }
}

impl From<GenericNetlinkMessageAttributeType> for TaskStatsAttributeType {
    fn from(genericNetlinkMessageAttributeType: GenericNetlinkMessageAttributeType) -> Self {
        Self::New(genericNetlinkMessageAttributeType.into())
    }
}

#[derive(Debug, Clone)]
pub enum TaskStatsCommandAttribute {
    UNSPECIFIED,
    PID(Tid),
    TGID(Pid),
    REGISTER_CPUMASK(String),
    DEREGISTER_CPUMASK(String),
}

impl TaskStatsCommandAttribute {
    pub fn Type(&self) -> TaskStatsCommandAttributeType {
        match self {
            Self::UNSPECIFIED => TaskStatsCommandAttributeType::UNSPECIFIED,
            Self::PID(_) => TaskStatsCommandAttributeType::PID,
            Self::TGID(_) => TaskStatsCommandAttributeType::TGID,
            Self::REGISTER_CPUMASK(_) => TaskStatsCommandAttributeType::REGISTER_CPUMASK,
            Self::DEREGISTER_CPUMASK(_) => TaskStatsCommandAttributeType::DEREGISTER_CPUMASK,
        }
    }
}

impl Into<TaskStatsAttribute> for TaskStatsCommandAttribute {
    fn into(self) -> TaskStatsAttribute {
        match self {
            Self::UNSPECIFIED => TaskStatsAttribute::New(self.Type().into(), [].to_vec()),
            Self::PID(tid) => TaskStatsAttribute::New(
                self.Type().into(),
                Into::<u32>::into(tid).to_le_bytes().to_vec(),
            ),
            Self::TGID(pid) => TaskStatsAttribute::New(
                self.Type().into(),
                Into::<u32>::into(pid).to_le_bytes().to_vec(),
            ),
            Self::REGISTER_CPUMASK(ref mask) => {
                let mut payload = mask.as_bytes().to_vec();
                payload.push(0);
                TaskStatsAttribute::New(self.Type().into(), payload)
            }
            Self::DEREGISTER_CPUMASK(ref mask) => {
                let mut payload = mask.as_bytes().to_vec();
                payload.push(0);
                TaskStatsAttribute::New(self.Type().into(), payload)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskStatsCommandAttributeType {
    UNSPECIFIED = 0,
    PID = 1,
    TGID = 2,
    REGISTER_CPUMASK = 3,
    DEREGISTER_CPUMASK = 4,
}

impl Into<GenericNetlinkMessageAttributeType> for TaskStatsCommandAttributeType {
    fn into(self) -> GenericNetlinkMessageAttributeType {
        unimplemented!();
    }
}

impl Into<TaskStatsAttributeType> for TaskStatsCommandAttributeType {
    fn into(self) -> TaskStatsAttributeType {
        TaskStatsAttributeType::New(self as u16)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TaskStatsResultAttributeAggregatePid {
    tid: Tid,
    stats: TaskStatsRaw,
}

impl TaskStatsResultAttributeAggregatePid {
    pub fn New(tid: Tid, stats: TaskStatsRaw) -> Self {
        Self { tid, stats }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TaskStatsResultAttributeAggregateTgid {
    pid: Pid,
    stats: TaskStatsRaw,
}

impl TaskStatsResultAttributeAggregateTgid {
    pub fn New(pid: Pid, stats: TaskStatsRaw) -> Self {
        Self { pid, stats }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum TaskStatsResultAttribute {
    UNSPECIFIED,
    PID(Tid),
    TGID(Pid),
    STATS(TaskStatsRaw),
    AGGR_PID(TaskStatsResultAttributeAggregatePid),
    AGGR_TGID(TaskStatsResultAttributeAggregateTgid),
    NULL,
}

impl TaskStatsResultAttribute {
    pub fn Type(&self) -> TaskStatsResultAttributeType {
        match self {
            Self::UNSPECIFIED => TaskStatsResultAttributeType::UNSPECIFIED,
            Self::PID(_) => TaskStatsResultAttributeType::PID,
            Self::TGID(_) => TaskStatsResultAttributeType::TGID,
            Self::STATS(_) => TaskStatsResultAttributeType::STATS,
            Self::AGGR_PID(_) => TaskStatsResultAttributeType::AGGR_PID,
            Self::AGGR_TGID(_) => TaskStatsResultAttributeType::AGGR_TGID,
            Self::NULL => TaskStatsResultAttributeType::NULL,
        }
    }
}

impl Into<GenericNetlinkMessageAttribute> for TaskStatsResultAttribute {
    fn into(self) -> GenericNetlinkMessageAttribute {
        match self {
            Self::UNSPECIFIED => {
                GenericNetlinkMessageAttribute::New(self.Type().into(), [].to_vec())
            }
            Self::PID(tid) => GenericNetlinkMessageAttribute::New(
                self.Type().into(),
                (Into::<u32>::into(tid)).to_le_bytes().to_vec(),
            ),
            Self::TGID(pid) => GenericNetlinkMessageAttribute::New(
                self.Type().into(),
                (Into::<u32>::into(pid)).to_le_bytes().to_vec(),
            ),
            Self::STATS(stats) => {
                GenericNetlinkMessageAttribute::New(self.Type().into(), stats.ToByteArray())
            }
            Self::AGGR_PID(_aggregatePid) => {
                unimplemented!()
            }
            Self::AGGR_TGID(_aggregateTgid) => {
                unimplemented!()
            }
            Self::NULL => GenericNetlinkMessageAttribute::New(self.Type().into(), [].to_vec()),
        }
    }
}

impl TryFrom<TaskStatsAttribute> for TaskStatsResultAttribute {
    type Error = TaskStatsError;

    fn try_from(taskStatsAttribute: TaskStatsAttribute) -> Result<Self, Self::Error> {
        let attributeType = taskStatsAttribute.Type().try_into()?;
        let payload = taskStatsAttribute.payload;

        match attributeType {
            TaskStatsResultAttributeType::UNSPECIFIED => Ok(Self::UNSPECIFIED),
            TaskStatsResultAttributeType::PID => Ok(Self::PID(Tid::New(u32::from_ne_bytes(
                payload[4..8].try_into().unwrap(),
            ) as usize))),
            TaskStatsResultAttributeType::TGID => Ok(Self::TGID(Pid::New(u32::from_ne_bytes(
                payload[4..8].try_into().unwrap(),
            ) as usize))),
            TaskStatsResultAttributeType::STATS => {
                Ok(Self::STATS(TaskStatsRaw::FromByteArray(&payload)?))
            }
            TaskStatsResultAttributeType::AGGR_PID => {
                let tid = Tid::New(u32::from_ne_bytes(payload[4..8].try_into().unwrap()) as usize);
                let stats = TaskStatsRaw::FromByteArray(&payload[12..])?;
                Ok(Self::AGGR_PID(TaskStatsResultAttributeAggregatePid::New(
                    tid, stats,
                )))
            }
            TaskStatsResultAttributeType::AGGR_TGID => {
                let pid = Pid::New(u32::from_ne_bytes(payload[4..8].try_into().unwrap()) as usize);
                let stats = TaskStatsRaw::FromByteArray(&payload[12..])?;

                Ok(Self::AGGR_TGID(TaskStatsResultAttributeAggregateTgid::New(
                    pid, stats,
                )))
            }
            TaskStatsResultAttributeType::NULL => Ok(Self::NULL),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskStatsResultAttributeType {
    UNSPECIFIED = 0, // Reserved
    PID = 1,         // Thread id
    TGID = 2,        // Thread group id
    STATS = 3,       // taskstats structure
    AGGR_PID = 4,    // contains pid + stats
    AGGR_TGID = 5,   // contains tgid + stats
    NULL = 6,        // contains nothing
}

impl Into<GenericNetlinkMessageAttributeType> for TaskStatsResultAttributeType {
    fn into(self) -> GenericNetlinkMessageAttributeType {
        GenericNetlinkMessageAttributeType::New(self as u16)
    }
}

impl Into<TaskStatsAttributeType> for TaskStatsResultAttributeType {
    fn into(self) -> TaskStatsAttributeType {
        TaskStatsAttributeType::New(self as u16)
    }
}

impl TryFrom<TaskStatsAttributeType> for TaskStatsResultAttributeType {
    type Error = TaskStatsError;

    fn try_from(taskStatsAttributeType: TaskStatsAttributeType) -> Result<Self, Self::Error> {
        match taskStatsAttributeType {
            x if x == Self::UNSPECIFIED.into() => Ok(Self::UNSPECIFIED),
            x if x == Self::PID.into() => Ok(Self::PID),
            x if x == Self::TGID.into() => Ok(Self::TGID),
            x if x == Self::STATS.into() => Ok(Self::STATS),
            x if x == Self::AGGR_PID.into() => Ok(Self::AGGR_PID),
            x if x == Self::AGGR_TGID.into() => Ok(Self::AGGR_TGID),
            x if x == Self::NULL.into() => Ok(Self::NULL),
            _ => Err(TaskStatsError::UNKNOWN_RESULT_ATTRIBUTE_TYPE(
                taskStatsAttributeType,
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TaskStatsMessage {
    command: TaskStatsCommand,
    familyId: u16,
    attributes: Vec<TaskStatsAttribute>,
}

impl TaskStatsMessage {
    pub fn New(familyId: u16, command: TaskStatsCommand) -> Self {
        Self {
            command,
            familyId,
            attributes: Vec::new(),
        }
    }

    pub fn AddCommandAttribute(&mut self, attribute: TaskStatsCommandAttribute) {
        self.attributes.push(attribute.into());
    }

    pub fn GetResultAttribute(
        &self,
        attributeType: TaskStatsResultAttributeType,
    ) -> Option<TaskStatsResultAttribute> {
        for attribute in &self.attributes {
            if attribute.Type() == attributeType.into() {
                return Some(attribute.clone().try_into().ok()?);
            }
        }

        None
    }
}

impl Into<GenericNetlinkMessage> for TaskStatsMessage {
    fn into(self) -> GenericNetlinkMessage {
        let mut genericNetlinkMessage = GenericNetlinkMessage::New(
            GenericNetlinkMessageType::New(self.familyId),
            self.command.into(),
        );

        for attribute in self.attributes {
            genericNetlinkMessage.AddAttribute(attribute.into());
        }

        genericNetlinkMessage
    }
}

impl TryFrom<GenericNetlinkMessage> for TaskStatsMessage {
    type Error = TaskStatsError;

    fn try_from(genericNetlinkMessage: GenericNetlinkMessage) -> Result<Self, Self::Error> {
        let familyId: u16 = genericNetlinkMessage.MessageType().into();
        let command = genericNetlinkMessage.Command().try_into()?;

        let mut attributes = Vec::new();

        for attribute in genericNetlinkMessage.attributes {
            attributes.push(attribute.into());
        }

        let result = Self {
            command,
            familyId,
            attributes,
        };

        Ok(result)
    }
}

#[derive(Debug)]
pub struct TaskStatsConnection {
    genericNetlinkConnection: GenericNetlinkConnection,
    taskStatsFamilyId: u16,
}

impl TaskStatsConnection {
    const TASKSTATS_FAMILY_NAME: &'static str = "TASKSTATS";

    pub fn New() -> Result<Self, TaskStatsError> {
        let genericNetlinkConnection = GenericNetlinkConnection::New()?;

        let mut getFamilyIdMessage =
            GenericNetlinkControlMessage::New(GenericNetlinkControlMessageCommand::GET_FAMILY_ID);

        getFamilyIdMessage.AddControlAttribute(GenericNetlinkControlMessageAttribute::FAMILY_NAME(
            String::from(Self::TASKSTATS_FAMILY_NAME),
        ));

        genericNetlinkConnection.Send(getFamilyIdMessage.into())?;

        let respondMessage = genericNetlinkConnection.Recv()?;
        let respondMessage: GenericNetlinkControlMessage = respondMessage.try_into()?;

        if let GenericNetlinkControlMessageAttribute::FAMILY_ID(familyId) = respondMessage
            .GetControlAttribute(GenericNetlinkControlMessageAttributeType::FAMILY_ID)
            .unwrap()
        {
            Ok(Self {
                genericNetlinkConnection,
                taskStatsFamilyId: familyId,
            })
        } else {
            Err(TaskStatsError::GET_FAMILY_ID_ERROR)
        }
    }

    pub fn GetThreadTaskStats(&self, realTid: Tid) -> Result<TaskStats, TaskStatsError> {
        let mut taskStatsMessage =
            TaskStatsMessage::New(self.taskStatsFamilyId, TaskStatsCommand::GET);

        taskStatsMessage.AddCommandAttribute(TaskStatsCommandAttribute::PID(realTid));

        self.genericNetlinkConnection
            .Send(taskStatsMessage.into())?;
        let respondMessage: TaskStatsMessage = self.genericNetlinkConnection.Recv()?.try_into()?;

        let result = respondMessage.GetResultAttribute(TaskStatsResultAttributeType::AGGR_PID);

        if result.is_none() {
            return Err(TaskStatsError::NO_AGGR_PID_ATTRIBUTE(respondMessage));
        }

        if let TaskStatsResultAttribute::AGGR_PID(result) = result.unwrap() {
            // check if we get the same tid we ask for
            if result.tid != realTid {
                return Err(TaskStatsError::WRONG_TID(result.tid));
            }

            Ok(result.stats.into())
        } else {
            Err(TaskStatsError::WRONG_RESULT_TYPE(result.unwrap()))
        }
    }

    pub fn GetProcessTaskStats(&self, realPid: Pid) -> Result<TaskStats, TaskStatsError> {
        let mut taskStatsMessage =
            TaskStatsMessage::New(self.taskStatsFamilyId, TaskStatsCommand::GET);

        taskStatsMessage.AddCommandAttribute(TaskStatsCommandAttribute::TGID(realPid));

        self.genericNetlinkConnection
            .Send(taskStatsMessage.into())?;
        let respondMessage: TaskStatsMessage = self.genericNetlinkConnection.Recv()?.try_into()?;

        let result = respondMessage.GetResultAttribute(TaskStatsResultAttributeType::AGGR_TGID);

        if result.is_none() {
            return Err(TaskStatsError::NO_AGGR_TGID_ATTRIBUTE(respondMessage));
        }

        if let TaskStatsResultAttribute::AGGR_TGID(result) = result.unwrap() {
            // check if we get the same pid we ask for
            if result.pid != realPid {
                return Err(TaskStatsError::WRONG_PID(result.pid));
            }

            Ok(result.stats.into())
        } else {
            Err(TaskStatsError::WRONG_RESULT_TYPE(result.unwrap()))
        }
    }
}

#[derive(Debug)]
pub enum TaskStatsError {
    GENERIC_ERROR(GenericError),
    UNSUPPORTED_TASKSTATS_VERSION(u16),
    GET_FAMILY_ID_ERROR,
    UNKNOWN_COMMAND(u8),
    NO_AGGR_PID_ATTRIBUTE(TaskStatsMessage),
    NO_AGGR_TGID_ATTRIBUTE(TaskStatsMessage),
    UNKNOWN_RESULT_ATTRIBUTE_TYPE(TaskStatsAttributeType),
    TASK_STRUCT_ERROR(Vec<u8>),
    WRONG_TID(Tid),
    WRONG_PID(Pid),
    WRONG_RESULT_TYPE(TaskStatsResultAttribute),
}

impl Error for TaskStatsError {}

impl fmt::Display for TaskStatsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let result = match self {
            Self::GENERIC_ERROR(error) => String::from(format!("Generic netlink error: {}", error)),
            Self::UNSUPPORTED_TASKSTATS_VERSION(version) => {
                String::from(format!("Unsupported taskstats version: {}", version))
            }
            Self::GET_FAMILY_ID_ERROR => String::from(format!("Can't get family id")),
            Self::UNKNOWN_COMMAND(command) => String::from(format!("Unknown command: {}", command)),
            Self::NO_AGGR_PID_ATTRIBUTE(taskStatsMessage) => {
                String::from(format!("No AGGR_PID attribute: {:?}", taskStatsMessage))
            }
            Self::NO_AGGR_TGID_ATTRIBUTE(taskStatsMessage) => {
                String::from(format!("No AGGR_TGID attribute: {:?}", taskStatsMessage))
            }
            Self::UNKNOWN_RESULT_ATTRIBUTE_TYPE(taskStatsAttributeType) => String::from(format!(
                "Unknown result attribute type: {:?}",
                taskStatsAttributeType
            )),
            Self::TASK_STRUCT_ERROR(buf) => {
                String::from(format!("Raw taskstats struct error: {:?}", buf))
            }
            Self::WRONG_TID(tid) => String::from(format!("Wrong tid from result: {:?}", tid)),
            Self::WRONG_PID(pid) => String::from(format!("Wrong pid from result: {:?}", pid)),
            Self::WRONG_RESULT_TYPE(taskStatsResultAttribute) => String::from(format!(
                "Wrong taskstats result attribute type: {:?}",
                taskStatsResultAttribute
            )),
        };

        write!(f, "{}", result)
    }
}

impl From<GenericError> for TaskStatsError {
    fn from(error: GenericError) -> Self {
        Self::GENERIC_ERROR(error)
    }
}
