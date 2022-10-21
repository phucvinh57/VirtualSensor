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
use crate::process::{Pid, Tid};

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
    cpu_delay_count: u64,
    cpu_delay_total: u64, // in nanoseconds

    block_io_delay_count: u64,
    block_io_delay_total: u64, // in nanoseconds

    swapin_delay_count: u64,
    swapin_delay_total: u64, // in nanoseconds

    cpu_runtime_real_total: u64,    // in nanoseconds
    cpu_runtime_virtual_total: u64, // in nanoseconds

    // basic fields
    command_str: [u8; Self::COMMAND_LENGTH],
    scheduling_discipline: u8,
    padding3: [u8; 3],
    padding4: [u8; 4],

    uid: u32,
    gid: u32,
    pid: u32,
    parent_pid: u32,

    begin_time: u32, // in seconds
    padding5: [u8; 4],
    elapsed_time: u64, // in microseconds

    user_cpu_time: u64,   // in microseconds
    system_cpu_time: u64, // in microseconds

    minor_fault_count: u64,
    major_fault_count: u64,

    // extended accounting fields
    accumulated_rss: u64, // in MB
    accumulated_vss: u64, // in MB

    high_water_rss: u64, // in KB
    high_water_vss: u64, // in KB

    io_read_bytes: u64,
    io_write_bytes: u64,

    read_syscall_count: u64,
    write_syscall_count: u64,

    // storage IO accounting fields
    block_io_read_bytes: u64,
    block_io_write_bytes: u64,
    cancelled_block_io_write_bytes: u64,

    voluntary_context_switches: u64,
    nonvoluntary_context_switches: u64,

    user_time_scaled: u64,
    system_time_scaled: u64,
    run_real_total_scaled: u64,

    free_pages_delay_count: u64,
    free_pages_delay_total: u64,
}

impl TaskStatsRawV8 {
    const LENGTH: usize = mem::size_of::<TaskStatsRawV8>();
    const VERSION: u16 = 8;
    const COMMAND_LENGTH: usize = 32;

    pub fn to_byte_array(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(unsafe {
            slice::from_raw_parts(self as *const _ as *const u8, Self::LENGTH)
        });
        result
    }

    pub fn from_byte_array(buf: &[u8]) -> Result<Self, TaskStatsError> {
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

    pub fn command_str(&self) -> String {
        std::str::from_utf8(&self.command_str)
            .unwrap()
            .to_string()
    }

    pub fn to_taskstats(&self) -> TaskStats {
        TaskStats {
            command_str: self.command_str(),
            pid: Pid::new(self.pid as usize),
            uid: Uid::new(self.uid as usize),
            gid: Gid::new(self.gid as usize),
            parent_pid: Pid::new(self.parent_pid as usize),
            nice: self.nice as isize,
            flags: self.flags as usize,
            exitcode: self.exitcode as usize,
            timestamp: Timestamp::get_curr_timestamp(),

            begin_time: UNIX_EPOCH + Duration::from_secs(self.begin_time as u64),
            elapsed_time: TimeCount::from_microsecs(self.elapsed_time.try_into().unwrap()),
            scheduling_discipline: self.scheduling_discipline,

            user_cpu_time: TimeCount::from_microsecs(self.user_cpu_time.try_into().unwrap()),
            system_cpu_time: TimeCount::from_microsecs(self.system_cpu_time.try_into().unwrap()),

            accumulated_rss: DataCount::from_mb(self.accumulated_rss.try_into().unwrap()),
            accumulated_vss: DataCount::from_mb(self.accumulated_vss.try_into().unwrap()),

            high_water_rss: DataCount::from_kb(self.high_water_rss.try_into().unwrap()),
            high_water_vss: DataCount::from_kb(self.high_water_vss.try_into().unwrap()),

            io_read: DataCount::from_byte(self.io_read_bytes.try_into().unwrap()),
            io_write: DataCount::from_byte(self.io_write_bytes.try_into().unwrap()),

            read_syscall_count: Count::new(self.read_syscall_count.try_into().unwrap()),
            write_syscall_count: Count::new(self.write_syscall_count.try_into().unwrap()),

            block_io_read: DataCount::from_byte(self.block_io_read_bytes.try_into().unwrap()),
            block_io_write: DataCount::from_byte(self.block_io_write_bytes.try_into().unwrap()),
            cancelled_block_io_write: DataCount::from_byte(
                self.cancelled_block_io_write_bytes.try_into().unwrap(),
            ),

            cpu_delay_count: Count::new(self.cpu_delay_count.try_into().unwrap()),
            cpu_delay_total: TimeCount::from_nanosecs(self.cpu_delay_total.try_into().unwrap()),

            minor_fault_count: Count::new(self.minor_fault_count.try_into().unwrap()),
            major_fault_count: Count::new(self.major_fault_count.try_into().unwrap()),

            free_pages_delay_count: Count::new(self.free_pages_delay_count.try_into().unwrap()),
            free_pages_delay_total: TimeCount::from_nanosecs(
                self.free_pages_delay_total.try_into().unwrap(),
            ),

            thrashing_delay_count: Count::new(0),
            thrashing_delay_total: TimeCount::from_nanosecs(0),

            block_io_delay_count: Count::new(self.block_io_delay_count.try_into().unwrap()),
            block_io_delay_total: TimeCount::from_nanosecs(
                self.block_io_delay_total.try_into().unwrap(),
            ),

            swapin_delay_count: Count::new(self.swapin_delay_count.try_into().unwrap()),
            swapin_delay_total: TimeCount::from_nanosecs(self.swapin_delay_total.try_into().unwrap()),

            memory_compact_delay_count: Count::new(0),
            memory_compact_delay_total: TimeCount::from_nanosecs(0),

            voluntary_context_switches: Count::new(self.voluntary_context_switches.try_into().unwrap()),
            nonvoluntary_context_switches: Count::new(
                self.nonvoluntary_context_switches.try_into().unwrap(),
            ),

            cpu_runtime_real_total: TimeCount::from_nanosecs(
                self.cpu_runtime_real_total.try_into().unwrap(),
            ),
            cpu_runtime_virtual_total: TimeCount::from_nanosecs(
                self.cpu_runtime_virtual_total.try_into().unwrap(),
            ),

            user_time_scaled: TimeCount::from_nanosecs(self.user_time_scaled.try_into().unwrap()),
            system_time_scaled: TimeCount::from_nanosecs(self.system_time_scaled.try_into().unwrap()),
            run_real_total_scaled: TimeCount::from_nanosecs(
                self.run_real_total_scaled.try_into().unwrap(),
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
    cpu_delay_count: u64,
    cpu_delay_total: u64, // in nanoseconds

    block_io_delay_count: u64,
    block_io_delay_total: u64, // in nanoseconds

    swapin_delay_count: u64,
    swapin_delay_total: u64, // in nanoseconds

    cpu_runtime_real_total: u64,    // in nanoseconds
    cpu_runtime_virtual_total: u64, // in nanoseconds

    // basic fields
    command_str: [u8; Self::COMMAND_LENGTH],
    scheduling_discipline: u8,
    padding3: [u8; 3],
    padding4: [u8; 4],

    uid: u32,
    gid: u32,
    pid: u32,
    parent_pid: u32,

    begin_time: u32, // in seconds
    padding5: [u8; 4],
    elapsed_time: u64, // in microseconds

    user_cpu_time: u64,   // in microseconds
    system_cpu_time: u64, // in microseconds

    minor_fault_count: u64,
    major_fault_count: u64,

    // extended accounting fields
    accumulated_rss: u64, // in MB
    accumulated_vss: u64, // in MB

    high_water_rss: u64, // in KB
    high_water_vss: u64, // in KB

    io_read_bytes: u64,
    io_write_bytes: u64,

    read_syscall_count: u64,
    write_syscall_count: u64,

    // storage IO accounting fields
    block_io_read_bytes: u64,
    block_io_write_bytes: u64,
    cancelled_block_io_write_bytes: u64,

    voluntary_context_switches: u64,
    nonvoluntary_context_switches: u64,

    user_time_scaled: u64,
    system_time_scaled: u64,
    run_real_total_scaled: u64,

    free_pages_delay_count: u64,
    free_pages_delay_total: u64,

    thrashing_delay_count: u64,
    thrashing_delay_total: u64,
}

impl TaskStatsRawV9 {
    const LENGTH: usize = mem::size_of::<TaskStatsRawV9>();
    const VERSION: u16 = 9;
    const COMMAND_LENGTH: usize = 32;

    pub fn to_byte_array(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(unsafe {
            slice::from_raw_parts(self as *const _ as *const u8, Self::LENGTH)
        });
        result
    }

    pub fn from_byte_array(buf: &[u8]) -> Result<Self, TaskStatsError> {
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

    pub fn get_command_str(&self) -> String {
        std::str::from_utf8(&self.command_str)
            .unwrap()
            .to_string()
    }

    pub fn to_taskstats(&self) -> TaskStats {
        TaskStats {
            command_str: self.get_command_str(),
            pid: Pid::new(self.pid as usize),
            uid: Uid::new(self.uid as usize),
            gid: Gid::new(self.gid as usize),
            parent_pid: Pid::new(self.parent_pid as usize),
            nice: self.nice as isize,
            flags: self.flags as usize,
            exitcode: self.exitcode as usize,
            timestamp: Timestamp::get_curr_timestamp(),

            begin_time: UNIX_EPOCH + Duration::from_secs(self.begin_time as u64),
            elapsed_time: TimeCount::from_microsecs(self.elapsed_time.try_into().unwrap()),
            scheduling_discipline: self.scheduling_discipline,

            user_cpu_time: TimeCount::from_microsecs(self.user_cpu_time.try_into().unwrap()),
            system_cpu_time: TimeCount::from_microsecs(self.system_cpu_time.try_into().unwrap()),

            accumulated_rss: DataCount::from_mb(self.accumulated_rss.try_into().unwrap()),
            accumulated_vss: DataCount::from_mb(self.accumulated_vss.try_into().unwrap()),

            high_water_rss: DataCount::from_kb(self.high_water_rss.try_into().unwrap()),
            high_water_vss: DataCount::from_kb(self.high_water_vss.try_into().unwrap()),

            io_read: DataCount::from_byte(self.io_read_bytes.try_into().unwrap()),
            io_write: DataCount::from_byte(self.io_write_bytes.try_into().unwrap()),

            read_syscall_count: Count::new(self.read_syscall_count.try_into().unwrap()),
            write_syscall_count: Count::new(self.write_syscall_count.try_into().unwrap()),

            block_io_read: DataCount::from_byte(self.block_io_read_bytes.try_into().unwrap()),
            block_io_write: DataCount::from_byte(self.block_io_write_bytes.try_into().unwrap()),
            cancelled_block_io_write: DataCount::from_byte(
                self.cancelled_block_io_write_bytes.try_into().unwrap(),
            ),

            cpu_delay_count: Count::new(self.cpu_delay_count.try_into().unwrap()),
            cpu_delay_total: TimeCount::from_nanosecs(self.cpu_delay_total.try_into().unwrap()),

            minor_fault_count: Count::new(self.minor_fault_count.try_into().unwrap()),
            major_fault_count: Count::new(self.major_fault_count.try_into().unwrap()),

            free_pages_delay_count: Count::new(self.free_pages_delay_count.try_into().unwrap()),
            free_pages_delay_total: TimeCount::from_nanosecs(
                self.free_pages_delay_total.try_into().unwrap(),
            ),

            thrashing_delay_count: Count::new(self.thrashing_delay_count.try_into().unwrap()),
            thrashing_delay_total: TimeCount::from_nanosecs(
                self.thrashing_delay_total.try_into().unwrap(),
            ),

            block_io_delay_count: Count::new(self.block_io_delay_count.try_into().unwrap()),
            block_io_delay_total: TimeCount::from_nanosecs(
                self.block_io_delay_total.try_into().unwrap(),
            ),

            swapin_delay_count: Count::new(self.swapin_delay_count.try_into().unwrap()),
            swapin_delay_total: TimeCount::from_nanosecs(self.swapin_delay_total.try_into().unwrap()),

            memory_compact_delay_count: Count::new(0),
            memory_compact_delay_total: TimeCount::from_nanosecs(0),

            voluntary_context_switches: Count::new(self.voluntary_context_switches.try_into().unwrap()),
            nonvoluntary_context_switches: Count::new(
                self.nonvoluntary_context_switches.try_into().unwrap(),
            ),

            cpu_runtime_real_total: TimeCount::from_nanosecs(
                self.cpu_runtime_real_total.try_into().unwrap(),
            ),
            cpu_runtime_virtual_total: TimeCount::from_nanosecs(
                self.cpu_runtime_virtual_total.try_into().unwrap(),
            ),

            user_time_scaled: TimeCount::from_nanosecs(self.user_time_scaled.try_into().unwrap()),
            system_time_scaled: TimeCount::from_nanosecs(self.system_time_scaled.try_into().unwrap()),
            run_real_total_scaled: TimeCount::from_nanosecs(
                self.run_real_total_scaled.try_into().unwrap(),
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
    cpu_delay_count: u64,
    cpu_delay_total: u64, // in nanoseconds

    block_io_delay_count: u64,
    block_io_delay_total: u64, // in nanoseconds

    swapin_delay_count: u64,
    swapin_delay_total: u64, // in nanoseconds

    cpu_runtime_real_total: u64,    // in nanoseconds
    cpu_runtime_virtual_total: u64, // in nanoseconds

    // basic fields
    command_str: [u8; Self::COMMAND_LENGTH],
    scheduling_discipline: u8,
    padding3: [u8; 3],
    padding4: [u8; 4],

    uid: u32,
    gid: u32,
    pid: u32,
    parent_pid: u32,

    begin_time: u32, // in seconds
    padding5: [u8; 4],
    elapsed_time: u64, // in microseconds

    user_cpu_time: u64,   // in microseconds
    system_cpu_time: u64, // in microseconds

    minor_fault_count: u64,
    major_fault_count: u64,

    // extended accounting fields
    accumulated_rss: u64, // in MB
    accumulated_vss: u64, // in MB

    high_water_rss: u64, // in KB
    high_water_vss: u64, // in KB

    io_read_bytes: u64,
    io_write_bytes: u64,

    read_syscall_count: u64,
    write_syscall_count: u64,

    // storage IO accounting fields
    block_io_read_bytes: u64,
    block_io_write_bytes: u64,
    cancelled_block_io_write_bytes: u64,

    voluntary_context_switches: u64,
    nonvoluntary_context_switches: u64,

    user_time_scaled: u64,
    system_time_scaled: u64,
    run_real_total_scaled: u64,

    free_pages_delay_count: u64,
    free_pages_delay_total: u64,

    thrashing_delay_count: u64,
    thrashing_delay_total: u64,

    begin_time64: u64,
}

impl TaskStatsRawV10 {
    const LENGTH: usize = mem::size_of::<TaskStatsRawV10>();
    const VERSION: u16 = 10;
    const COMMAND_LENGTH: usize = 32;

    pub fn to_byte_array(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(unsafe {
            slice::from_raw_parts(self as *const _ as *const u8, Self::LENGTH)
        });
        result
    }

    pub fn from_byte_array(buf: &[u8]) -> Result<Self, TaskStatsError> {
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

    pub fn command_str(&self) -> String {
        std::str::from_utf8(&self.command_str)
            .unwrap()
            .to_string()
    }

    pub fn to_taskstats(&self) -> TaskStats {
        TaskStats {
            command_str: self.command_str(),
            pid: Pid::new(self.pid as usize),
            uid: Uid::new(self.uid as usize),
            gid: Gid::new(self.gid as usize),
            parent_pid: Pid::new(self.parent_pid as usize),
            nice: self.nice as isize,
            flags: self.flags as usize,
            exitcode: self.exitcode as usize,
            timestamp: Timestamp::get_curr_timestamp(),

            begin_time: UNIX_EPOCH + Duration::from_secs(self.begin_time as u64),
            elapsed_time: TimeCount::from_microsecs(self.elapsed_time.try_into().unwrap()),
            scheduling_discipline: self.scheduling_discipline,

            user_cpu_time: TimeCount::from_microsecs(self.user_cpu_time.try_into().unwrap()),
            system_cpu_time: TimeCount::from_microsecs(self.system_cpu_time.try_into().unwrap()),

            accumulated_rss: DataCount::from_mb(self.accumulated_rss.try_into().unwrap()),
            accumulated_vss: DataCount::from_mb(self.accumulated_vss.try_into().unwrap()),

            high_water_rss: DataCount::from_kb(self.high_water_rss.try_into().unwrap()),
            high_water_vss: DataCount::from_kb(self.high_water_vss.try_into().unwrap()),

            io_read: DataCount::from_byte(self.io_read_bytes.try_into().unwrap()),
            io_write: DataCount::from_byte(self.io_write_bytes.try_into().unwrap()),

            read_syscall_count: Count::new(self.read_syscall_count.try_into().unwrap()),
            write_syscall_count: Count::new(self.write_syscall_count.try_into().unwrap()),

            block_io_read: DataCount::from_byte(self.block_io_read_bytes.try_into().unwrap()),
            block_io_write: DataCount::from_byte(self.block_io_write_bytes.try_into().unwrap()),
            cancelled_block_io_write: DataCount::from_byte(
                self.cancelled_block_io_write_bytes.try_into().unwrap(),
            ),

            cpu_delay_count: Count::new(self.cpu_delay_count.try_into().unwrap()),
            cpu_delay_total: TimeCount::from_nanosecs(self.cpu_delay_total.try_into().unwrap()),

            minor_fault_count: Count::new(self.minor_fault_count.try_into().unwrap()),
            major_fault_count: Count::new(self.major_fault_count.try_into().unwrap()),

            free_pages_delay_count: Count::new(self.free_pages_delay_count.try_into().unwrap()),
            free_pages_delay_total: TimeCount::from_nanosecs(
                self.free_pages_delay_total.try_into().unwrap(),
            ),

            thrashing_delay_count: Count::new(self.thrashing_delay_count.try_into().unwrap()),
            thrashing_delay_total: TimeCount::from_nanosecs(
                self.thrashing_delay_total.try_into().unwrap(),
            ),

            block_io_delay_count: Count::new(self.block_io_delay_count.try_into().unwrap()),
            block_io_delay_total: TimeCount::from_nanosecs(
                self.block_io_delay_total.try_into().unwrap(),
            ),

            swapin_delay_count: Count::new(self.swapin_delay_count.try_into().unwrap()),
            swapin_delay_total: TimeCount::from_nanosecs(self.swapin_delay_total.try_into().unwrap()),

            memory_compact_delay_count: Count::new(0),
            memory_compact_delay_total: TimeCount::from_nanosecs(0),

            voluntary_context_switches: Count::new(self.voluntary_context_switches.try_into().unwrap()),
            nonvoluntary_context_switches: Count::new(
                self.nonvoluntary_context_switches.try_into().unwrap(),
            ),

            cpu_runtime_real_total: TimeCount::from_nanosecs(
                self.cpu_runtime_real_total.try_into().unwrap(),
            ),
            cpu_runtime_virtual_total: TimeCount::from_nanosecs(
                self.cpu_runtime_virtual_total.try_into().unwrap(),
            ),

            user_time_scaled: TimeCount::from_nanosecs(self.user_time_scaled.try_into().unwrap()),
            system_time_scaled: TimeCount::from_nanosecs(self.system_time_scaled.try_into().unwrap()),
            run_real_total_scaled: TimeCount::from_nanosecs(
                self.run_real_total_scaled.try_into().unwrap(),
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
    cpu_delay_count: u64,
    cpu_delay_total: u64, // in nanoseconds

    block_io_delay_count: u64,
    block_io_delay_total: u64, // in nanoseconds

    swapin_delay_count: u64,
    swapin_delay_total: u64, // in nanoseconds

    cpu_runtime_real_total: u64,    // in nanoseconds
    cpu_runtime_virtual_total: u64, // in nanoseconds

    // basic fields
    command_str: [u8; Self::COMMAND_LENGTH],
    scheduling_discipline: u8,
    padding3: [u8; 3],
    padding4: [u8; 4],

    uid: u32,
    gid: u32,
    pid: u32,
    parent_pid: u32,

    begin_time: u32, // in seconds
    padding5: [u8; 4],
    elapsed_time: u64, // in microseconds

    user_cpu_time: u64,   // in microseconds
    system_cpu_time: u64, // in microseconds

    minor_fault_count: u64,
    major_fault_count: u64,

    // extended accounting fields
    accumulated_rss: u64, // in MB
    accumulated_vss: u64, // in MB

    high_water_rss: u64, // in KB
    high_water_vss: u64, // in KB

    io_read_bytes: u64,
    io_write_bytes: u64,

    read_syscall_count: u64,
    write_syscall_count: u64,

    // storage IO accounting fields
    block_io_read_bytes: u64,
    block_io_write_bytes: u64,
    cancelled_block_io_write_bytes: u64,

    voluntary_context_switches: u64,
    nonvoluntary_context_switches: u64,

    user_time_scaled: u64,
    system_time_scaled: u64,
    run_real_total_scaled: u64,

    free_pages_delay_count: u64,
    free_pages_delay_total: u64,

    thrashing_delay_count: u64,
    thrashing_delay_total: u64,

    begin_time64: u64,

    memory_compact_delay_count: u64,
    memory_compact_delay_total: u64,
}

impl TaskStatsRawV11 {
    const LENGTH: usize = mem::size_of::<TaskStatsRawV11>();
    const VERSION: u16 = 11;
    const COMMAND_LENGTH: usize = 32;

    pub fn to_byte_array(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(unsafe {
            slice::from_raw_parts(self as *const _ as *const u8, Self::LENGTH)
        });
        result
    }

    pub fn from_byte_array(buf: &[u8]) -> Result<Self, TaskStatsError> {
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

    pub fn command_str(&self) -> String {
        std::str::from_utf8(&self.command_str)
            .unwrap()
            .to_string()
    }

    pub fn to_taskstats(&self) -> TaskStats {
        TaskStats {
            command_str: self.command_str(),
            pid: Pid::new(self.pid as usize),
            uid: Uid::new(self.uid as usize),
            gid: Gid::new(self.gid as usize),
            parent_pid: Pid::new(self.parent_pid as usize),
            nice: self.nice as isize,
            flags: self.flags as usize,
            exitcode: self.exitcode as usize,
            timestamp: Timestamp::get_curr_timestamp(),

            begin_time: UNIX_EPOCH + Duration::from_secs(self.begin_time as u64),
            elapsed_time: TimeCount::from_microsecs(self.elapsed_time.try_into().unwrap()),
            scheduling_discipline: self.scheduling_discipline,

            user_cpu_time: TimeCount::from_microsecs(self.user_cpu_time.try_into().unwrap()),
            system_cpu_time: TimeCount::from_microsecs(self.system_cpu_time.try_into().unwrap()),

            accumulated_rss: DataCount::from_mb(self.accumulated_rss.try_into().unwrap()),
            accumulated_vss: DataCount::from_mb(self.accumulated_vss.try_into().unwrap()),

            high_water_rss: DataCount::from_kb(self.high_water_rss.try_into().unwrap()),
            high_water_vss: DataCount::from_kb(self.high_water_vss.try_into().unwrap()),

            io_read: DataCount::from_byte(self.io_read_bytes.try_into().unwrap()),
            io_write: DataCount::from_byte(self.io_write_bytes.try_into().unwrap()),

            read_syscall_count: Count::new(self.read_syscall_count.try_into().unwrap()),
            write_syscall_count: Count::new(self.write_syscall_count.try_into().unwrap()),

            block_io_read: DataCount::from_byte(self.block_io_read_bytes.try_into().unwrap()),
            block_io_write: DataCount::from_byte(self.block_io_write_bytes.try_into().unwrap()),
            cancelled_block_io_write: DataCount::from_byte(
                self.cancelled_block_io_write_bytes.try_into().unwrap(),
            ),

            cpu_delay_count: Count::new(self.cpu_delay_count.try_into().unwrap()),
            cpu_delay_total: TimeCount::from_nanosecs(self.cpu_delay_total.try_into().unwrap()),

            minor_fault_count: Count::new(self.minor_fault_count.try_into().unwrap()),
            major_fault_count: Count::new(self.major_fault_count.try_into().unwrap()),

            free_pages_delay_count: Count::new(self.free_pages_delay_count.try_into().unwrap()),
            free_pages_delay_total: TimeCount::from_nanosecs(
                self.free_pages_delay_total.try_into().unwrap(),
            ),

            thrashing_delay_count: Count::new(self.thrashing_delay_count.try_into().unwrap()),
            thrashing_delay_total: TimeCount::from_nanosecs(
                self.thrashing_delay_total.try_into().unwrap(),
            ),

            block_io_delay_count: Count::new(self.block_io_delay_count.try_into().unwrap()),
            block_io_delay_total: TimeCount::from_nanosecs(
                self.block_io_delay_total.try_into().unwrap(),
            ),

            swapin_delay_count: Count::new(self.swapin_delay_count.try_into().unwrap()),
            swapin_delay_total: TimeCount::from_nanosecs(self.swapin_delay_total.try_into().unwrap()),

            memory_compact_delay_count: Count::new(self.memory_compact_delay_count.try_into().unwrap()),
            memory_compact_delay_total: TimeCount::from_nanosecs(
                self.memory_compact_delay_total.try_into().unwrap(),
            ),

            voluntary_context_switches: Count::new(self.voluntary_context_switches.try_into().unwrap()),
            nonvoluntary_context_switches: Count::new(
                self.nonvoluntary_context_switches.try_into().unwrap(),
            ),

            cpu_runtime_real_total: TimeCount::from_nanosecs(
                self.cpu_runtime_real_total.try_into().unwrap(),
            ),
            cpu_runtime_virtual_total: TimeCount::from_nanosecs(
                self.cpu_runtime_virtual_total.try_into().unwrap(),
            ),

            user_time_scaled: TimeCount::from_nanosecs(self.user_time_scaled.try_into().unwrap()),
            system_time_scaled: TimeCount::from_nanosecs(self.system_time_scaled.try_into().unwrap()),
            run_real_total_scaled: TimeCount::from_nanosecs(
                self.run_real_total_scaled.try_into().unwrap(),
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
    pub fn to_byte_array(&self) -> Vec<u8> {
        match self {
            Self::V8(stats) => stats.to_byte_array(),
            Self::V9(stats) => stats.to_byte_array(),
            Self::V10(stats) => stats.to_byte_array(),
            Self::V11(stats) => stats.to_byte_array(),
        }
    }

    pub fn from_byte_array(buf: &[u8]) -> Result<Self, TaskStatsError> {
        // get version
        let version = u16::from_ne_bytes(buf[0..2].try_into().unwrap());

        match version {
            8 => Ok(Self::V8(TaskStatsRawV8::from_byte_array(buf)?)),
            9 => Ok(Self::V9(TaskStatsRawV9::from_byte_array(buf)?)),
            10 => Ok(Self::V10(TaskStatsRawV10::from_byte_array(buf)?)),
            11 => Ok(Self::V11(TaskStatsRawV11::from_byte_array(buf)?)),
            _ => Err(TaskStatsError::UNSUPPORTED_TASKSTATS_VERSION(version)),
        }
    }

    pub fn to_taskstats(&self) -> TaskStats {
        match self {
            Self::V8(stats) => stats.to_taskstats(),
            Self::V9(stats) => stats.to_taskstats(),
            Self::V10(stats) => stats.to_taskstats(),
            Self::V11(stats) => stats.to_taskstats(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TaskStats {
    pub command_str: String,
    pub pid: Pid,
    pub uid: Uid,
    pub gid: Gid,
    pub parent_pid: Pid,
    pub nice: isize,
    pub flags: usize,
    pub exitcode: usize,
    pub timestamp: Timestamp,

    pub begin_time: SystemTime,
    pub elapsed_time: TimeCount,
    pub scheduling_discipline: u8,

    pub user_cpu_time: TimeCount,
    pub system_cpu_time: TimeCount,

    pub accumulated_rss: DataCount,
    pub accumulated_vss: DataCount,

    pub high_water_rss: DataCount,
    pub high_water_vss: DataCount,

    pub io_read: DataCount,
    pub io_write: DataCount,

    pub read_syscall_count: Count,
    pub write_syscall_count: Count,

    pub block_io_read: DataCount,
    pub block_io_write: DataCount,
    pub cancelled_block_io_write: DataCount,

    pub cpu_delay_count: Count,
    pub cpu_delay_total: TimeCount,

    pub minor_fault_count: Count,
    pub major_fault_count: Count,

    pub free_pages_delay_count: Count,
    pub free_pages_delay_total: TimeCount,

    pub thrashing_delay_count: Count,
    pub thrashing_delay_total: TimeCount,

    pub block_io_delay_count: Count,
    pub block_io_delay_total: TimeCount,

    pub swapin_delay_count: Count,
    pub swapin_delay_total: TimeCount,

    pub memory_compact_delay_count: Count,
    pub memory_compact_delay_total: TimeCount,

    pub voluntary_context_switches: Count,
    pub nonvoluntary_context_switches: Count,

    pub cpu_runtime_real_total: TimeCount,
    pub cpu_runtime_virtual_total: TimeCount,

    pub user_time_scaled: TimeCount,
    pub system_time_scaled: TimeCount,
    pub run_real_total_scaled: TimeCount,
}

impl TaskStats {}

impl From<TaskStatsRaw> for TaskStats {
    fn from(taskstats_raw: TaskStatsRaw) -> Self {
        taskstats_raw.to_taskstats()
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
        GenericNetlinkMessageCommand::new(self as u8)
    }
}

impl TryFrom<GenericNetlinkMessageCommand> for TaskStatsCommand {
    type Error = TaskStatsError;

    fn try_from(
        generic_netlink_msg_cmd: GenericNetlinkMessageCommand,
    ) -> Result<Self, Self::Error> {
        let command = generic_netlink_msg_cmd.into();

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
    attr_type: TaskStatsAttributeType,
    payload: Vec<u8>,
}

impl TaskStatsAttribute {
    pub fn new(attr_type: TaskStatsAttributeType, payload: Vec<u8>) -> Self {
        Self {
            attr_type,
            payload,
        }
    }

    pub fn get_type(&self) -> TaskStatsAttributeType {
        self.attr_type
    }
}

impl Into<GenericNetlinkMessageAttribute> for TaskStatsAttribute {
    fn into(self) -> GenericNetlinkMessageAttribute {
        GenericNetlinkMessageAttribute::new(self.attr_type.into(), self.payload)
    }
}

impl From<GenericNetlinkMessageAttribute> for TaskStatsAttribute {
    fn from(generic_netlink_msg_attr: GenericNetlinkMessageAttribute) -> Self {
        TaskStatsAttribute::new(
            generic_netlink_msg_attr.get_type().into(),
            generic_netlink_msg_attr.payload,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskStatsAttributeType(u16);

impl TaskStatsAttributeType {
    pub fn new(value: u16) -> Self {
        Self(value)
    }
}

impl Into<GenericNetlinkMessageAttributeType> for TaskStatsAttributeType {
    fn into(self) -> GenericNetlinkMessageAttributeType {
        GenericNetlinkMessageAttributeType::new(self.0)
    }
}

impl From<GenericNetlinkMessageAttributeType> for TaskStatsAttributeType {
    fn from(generic_netlink_msg_attr_type: GenericNetlinkMessageAttributeType) -> Self {
        Self::new(generic_netlink_msg_attr_type.into())
    }
}

#[derive(Debug, Clone)]
pub enum TaskStatsCommandAttribute {
    Unspecified,
    // ??????????
    PID(Tid),
    // ??????????
    TGID(Pid),
    RegisterCPUMask(String),
    DeregisterCpuMask(String),
}

impl TaskStatsCommandAttribute {
    pub fn get_type(&self) -> TaskStatsCommandAttributeType {
        match self {
            Self::Unspecified => TaskStatsCommandAttributeType::Unspecified,
            Self::PID(_) => TaskStatsCommandAttributeType::PID,
            Self::TGID(_) => TaskStatsCommandAttributeType::TGID,
            Self::RegisterCPUMask(_) => TaskStatsCommandAttributeType::RegisterCPUMask,
            Self::DeregisterCpuMask(_) => TaskStatsCommandAttributeType::DeregisterCPUMask,
        }
    }
}

impl Into<TaskStatsAttribute> for TaskStatsCommandAttribute {
    fn into(self) -> TaskStatsAttribute {
        match self {
            Self::Unspecified => TaskStatsAttribute::new(self.get_type().into(), [].to_vec()),
            Self::PID(tid) => TaskStatsAttribute::new(
                self.get_type().into(),
                Into::<u32>::into(tid).to_le_bytes().to_vec(),
            ),
            Self::TGID(pid) => TaskStatsAttribute::new(
                self.get_type().into(),
                Into::<u32>::into(pid).to_le_bytes().to_vec(),
            ),
            Self::RegisterCPUMask(ref mask) => {
                let mut payload = mask.as_bytes().to_vec();
                payload.push(0);
                TaskStatsAttribute::new(self.get_type().into(), payload)
            }
            Self::DeregisterCpuMask(ref mask) => {
                let mut payload = mask.as_bytes().to_vec();
                payload.push(0);
                TaskStatsAttribute::new(self.get_type().into(), payload)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskStatsCommandAttributeType {
    Unspecified = 0,
    PID = 1,
    TGID = 2,
    RegisterCPUMask = 3,
    DeregisterCPUMask = 4,
}

impl Into<GenericNetlinkMessageAttributeType> for TaskStatsCommandAttributeType {
    fn into(self) -> GenericNetlinkMessageAttributeType {
        unimplemented!();
    }
}

impl Into<TaskStatsAttributeType> for TaskStatsCommandAttributeType {
    fn into(self) -> TaskStatsAttributeType {
        TaskStatsAttributeType::new(self as u16)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TaskStatsResultAttributeAggregatePid {
    tid: Tid,
    stats: TaskStatsRaw,
}

impl TaskStatsResultAttributeAggregatePid {
    pub fn new(tid: Tid, stats: TaskStatsRaw) -> Self {
        Self { tid, stats }
    }
}

#[derive(Debug, Clone, Copy)]
#[allow(unused)]
pub struct TaskStatsResultAttributeAggregateTgid {
    pid: Pid,
    stats: TaskStatsRaw,
}

impl TaskStatsResultAttributeAggregateTgid {
    pub fn new(pid: Pid, stats: TaskStatsRaw) -> Self {
        Self { pid, stats }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum TaskStatsResultAttribute {
    Unspecified,
    PID(Tid),
    TGID(Pid),
    Stats(TaskStatsRaw),
    AggrPid(TaskStatsResultAttributeAggregatePid),
    AggrTGid(TaskStatsResultAttributeAggregateTgid),
    NULL,
}

impl TaskStatsResultAttribute {
    pub fn get_type(&self) -> TaskStatsResultAttributeType {
        match self {
            Self::Unspecified => TaskStatsResultAttributeType::Unspecified,
            Self::PID(_) => TaskStatsResultAttributeType::PID,
            Self::TGID(_) => TaskStatsResultAttributeType::TGID,
            Self::Stats(_) => TaskStatsResultAttributeType::Stats,
            Self::AggrPid(_) => TaskStatsResultAttributeType::AggrPid,
            Self::AggrTGid(_) => TaskStatsResultAttributeType::AggrTGid,
            Self::NULL => TaskStatsResultAttributeType::NULL,
        }
    }
}

impl Into<GenericNetlinkMessageAttribute> for TaskStatsResultAttribute {
    fn into(self) -> GenericNetlinkMessageAttribute {
        match self {
            Self::Unspecified => {
                GenericNetlinkMessageAttribute::new(self.get_type().into(), [].to_vec())
            }
            Self::PID(tid) => GenericNetlinkMessageAttribute::new(
                self.get_type().into(),
                (Into::<u32>::into(tid)).to_le_bytes().to_vec(),
            ),
            Self::TGID(pid) => GenericNetlinkMessageAttribute::new(
                self.get_type().into(),
                (Into::<u32>::into(pid)).to_le_bytes().to_vec(),
            ),
            Self::Stats(stats) => {
                GenericNetlinkMessageAttribute::new(self.get_type().into(), stats.to_byte_array())
            }
            Self::AggrPid(_aggregate_pid) => {
                unimplemented!()
            }
            Self::AggrTGid(_aggregate_tgid) => {
                unimplemented!()
            }
            Self::NULL => GenericNetlinkMessageAttribute::new(self.get_type().into(), [].to_vec()),
        }
    }
}

impl TryFrom<TaskStatsAttribute> for TaskStatsResultAttribute {
    type Error = TaskStatsError;

    fn try_from(taskstats_attribute: TaskStatsAttribute) -> Result<Self, Self::Error> {
        let attribute_type = taskstats_attribute.get_type().try_into()?;
        let payload = taskstats_attribute.payload;

        match attribute_type {
            TaskStatsResultAttributeType::Unspecified => Ok(Self::Unspecified),
            TaskStatsResultAttributeType::PID => Ok(Self::PID(Tid::new(u32::from_ne_bytes(
                payload[4..8].try_into().unwrap(),
            ) as usize))),
            TaskStatsResultAttributeType::TGID => Ok(Self::TGID(Pid::new(u32::from_ne_bytes(
                payload[4..8].try_into().unwrap(),
            ) as usize))),
            TaskStatsResultAttributeType::Stats => {
                Ok(Self::Stats(TaskStatsRaw::from_byte_array(&payload)?))
            }
            TaskStatsResultAttributeType::AggrPid => {
                let tid = Tid::new(u32::from_ne_bytes(payload[4..8].try_into().unwrap()) as usize);
                let stats = TaskStatsRaw::from_byte_array(&payload[12..])?;
                Ok(Self::AggrPid(TaskStatsResultAttributeAggregatePid::new(
                    tid, stats,
                )))
            }
            TaskStatsResultAttributeType::AggrTGid => {
                let pid = Pid::new(u32::from_ne_bytes(payload[4..8].try_into().unwrap()) as usize);
                let stats = TaskStatsRaw::from_byte_array(&payload[12..])?;

                Ok(Self::AggrTGid(TaskStatsResultAttributeAggregateTgid::new(
                    pid, stats,
                )))
            }
            TaskStatsResultAttributeType::NULL => Ok(Self::NULL),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskStatsResultAttributeType {
    Unspecified = 0, // Reserved
    PID = 1,         // Thread id
    TGID = 2,        // Thread group id
    Stats = 3,       // taskstats structure
    AggrPid = 4,    // contains pid + stats
    AggrTGid = 5,   // contains tgid + stats
    NULL = 6,        // contains nothing
}

impl Into<GenericNetlinkMessageAttributeType> for TaskStatsResultAttributeType {
    fn into(self) -> GenericNetlinkMessageAttributeType {
        GenericNetlinkMessageAttributeType::new(self as u16)
    }
}

impl Into<TaskStatsAttributeType> for TaskStatsResultAttributeType {
    fn into(self) -> TaskStatsAttributeType {
        TaskStatsAttributeType::new(self as u16)
    }
}

impl TryFrom<TaskStatsAttributeType> for TaskStatsResultAttributeType {
    type Error = TaskStatsError;

    fn try_from(taskstats_attr_type: TaskStatsAttributeType) -> Result<Self, Self::Error> {
        match taskstats_attr_type {
            x if x == Self::Unspecified.into() => Ok(Self::Unspecified),
            x if x == Self::PID.into() => Ok(Self::PID),
            x if x == Self::TGID.into() => Ok(Self::TGID),
            x if x == Self::Stats.into() => Ok(Self::Stats),
            x if x == Self::AggrPid.into() => Ok(Self::AggrPid),
            x if x == Self::AggrTGid.into() => Ok(Self::AggrTGid),
            x if x == Self::NULL.into() => Ok(Self::NULL),
            _ => Err(TaskStatsError::UNKNOWN_RESULT_ATTRIBUTE_TYPE(
                taskstats_attr_type,
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TaskStatsMessage {
    command: TaskStatsCommand,
    family_id: u16,
    attributes: Vec<TaskStatsAttribute>,
}

impl TaskStatsMessage {
    pub fn New(familyId: u16, command: TaskStatsCommand) -> Self {
        Self {
            command,
            family_id: familyId,
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
            if attribute.get_type() == attributeType.into() {
                return Some(attribute.clone().try_into().ok()?);
            }
        }

        None
    }
}

impl Into<GenericNetlinkMessage> for TaskStatsMessage {
    fn into(self) -> GenericNetlinkMessage {
        let mut genericNetlinkMessage = GenericNetlinkMessage::new(
            GenericNetlinkMessageType::new(self.family_id),
            self.command.into(),
        );

        for attribute in self.attributes {
            genericNetlinkMessage.add_attr(attribute.into());
        }

        genericNetlinkMessage
    }
}

impl TryFrom<GenericNetlinkMessage> for TaskStatsMessage {
    type Error = TaskStatsError;

    fn try_from(genericNetlinkMessage: GenericNetlinkMessage) -> Result<Self, Self::Error> {
        let familyId: u16 = genericNetlinkMessage.get_message_type().into();
        let command = genericNetlinkMessage.get_command().try_into()?;

        let mut attributes = Vec::new();

        for attribute in genericNetlinkMessage.attributes {
            attributes.push(attribute.into());
        }

        let result = Self {
            command,
            family_id: familyId,
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

    pub fn new() -> Result<Self, TaskStatsError> {
        let genericNetlinkConnection = GenericNetlinkConnection::new()?;

        let mut getFamilyIdMessage =
            GenericNetlinkControlMessage::new(GenericNetlinkControlMessageCommand::GetFamilyId);

        getFamilyIdMessage.add_ctrl_attr(GenericNetlinkControlMessageAttribute::FamilyName(
            String::from(Self::TASKSTATS_FAMILY_NAME),
        ));

        genericNetlinkConnection.send(getFamilyIdMessage.into())?;

        let respondMessage = genericNetlinkConnection.recv()?;
        let respondMessage: GenericNetlinkControlMessage = respondMessage.try_into()?;

        if let GenericNetlinkControlMessageAttribute::FamilyId(familyId) = respondMessage
            .get_ctrl_attr(GenericNetlinkControlMessageAttributeType::FamilyId)
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

    pub fn get_thread_taskstats(&self, realTid: Tid) -> Result<TaskStats, TaskStatsError> {
        let mut taskStatsMessage =
            TaskStatsMessage::New(self.taskStatsFamilyId, TaskStatsCommand::GET);

        taskStatsMessage.AddCommandAttribute(TaskStatsCommandAttribute::PID(realTid));

        self.genericNetlinkConnection
            .send(taskStatsMessage.into())?;
        let respondMessage: TaskStatsMessage = self.genericNetlinkConnection.recv()?.try_into()?;

        let result = respondMessage.GetResultAttribute(TaskStatsResultAttributeType::AggrPid);

        if result.is_none() {
            return Err(TaskStatsError::NO_AGGR_PID_ATTRIBUTE(respondMessage));
        }

        if let TaskStatsResultAttribute::AggrPid(result) = result.unwrap() {
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
            .send(taskStatsMessage.into())?;
        let respondMessage: TaskStatsMessage = self.genericNetlinkConnection.recv()?.try_into()?;

        let result = respondMessage.GetResultAttribute(TaskStatsResultAttributeType::AggrTGid);

        if result.is_none() {
            return Err(TaskStatsError::NO_AGGR_TGID_ATTRIBUTE(respondMessage));
        }

        if let TaskStatsResultAttribute::AggrTGid(result) = result.unwrap() {
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
