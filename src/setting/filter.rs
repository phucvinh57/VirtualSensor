use serde::Deserialize;

#[derive(Deserialize, Clone, Copy, Debug)]
pub struct InterfaceRawStat {
    iname: bool,
    description: bool,
    uni_connection_stats: bool,
}
impl InterfaceRawStat {
    pub fn has_iname(&self) -> bool {
        self.iname
    }
    pub fn has_description(&self) -> bool {
        self.description
    }
    pub fn has_uni_connection_stats(&self) -> bool {
        self.uni_connection_stats
    }
}

#[derive(Deserialize, Clone, Copy, Debug)]
pub struct NetworkRawStat {
    interface_rawstat: InterfaceRawStat,
}
impl NetworkRawStat {
    pub fn get_irawstat(&self) -> InterfaceRawStat {
        self.interface_rawstat
    }
}

#[derive(Deserialize, Clone, Copy, Debug)]
pub struct InterfaceStat {
    iname: bool,
    packet_sent: bool,
    packet_recv: bool,
    total_data_sent: bool,
    total_data_recv: bool,
    real_data_sent: bool,
    real_data_recv: bool,
    connection_stats: bool,
}

impl InterfaceStat {
    pub fn has_iname(&self) -> bool {
        self.iname
    }
    pub fn has_packet_sent(&self) -> bool {
        self.packet_sent
    }
    pub fn has_packet_recv(&self) -> bool {
        self.packet_recv
    }
    pub fn has_total_data_sent(&self) -> bool {
        self.total_data_sent
    }
    pub fn has_total_data_recv(&self) -> bool {
        self.total_data_recv
    }
    pub fn has_real_data_sent(&self) -> bool {
        self.real_data_sent
    }
    pub fn has_real_data_recv(&self) -> bool {
        self.real_data_recv
    }
    pub fn has_connection_stats(&self) -> bool {
        self.connection_stats
    }
}

#[derive(Deserialize, Clone, Copy, Debug)]
pub struct NetworkStat {
    pack_sent: bool,
    pack_recv: bool,
    total_data_sent: bool,
    total_data_recv: bool,
    real_data_sent: bool,
    real_data_recv: bool,

    interface_stat: InterfaceStat,
}

impl NetworkStat {
    pub fn get_interface_stat(&self) -> &InterfaceStat {
        &self.interface_stat
    }

    pub fn has_pack_sent(&self) -> bool {
        self.pack_sent
    }
    pub fn has_pack_recv(&self) -> bool {
        self.pack_recv
    }
    pub fn has_total_data_sent(&self) -> bool {
        self.total_data_sent
    }
    pub fn has_total_data_recv(&self) -> bool {
        self.total_data_recv
    }
    pub fn has_real_data_sent(&self) -> bool {
        self.real_data_sent
    }
    pub fn has_real_data_recv(&self) -> bool {
        self.real_data_recv
    }
}

#[derive(Deserialize, Clone, Copy, Debug)]
pub struct ProcessStat {
    timestamp: bool,
    total_system_cpu_time: bool,
    total_user_cpu_time: bool,
    total_cpu_time: bool,
    total_rss: bool,
    total_vss: bool,
    total_swap: bool,
    total_io_read: bool,
    total_io_write: bool,
    total_block_io_read: bool,
    total_block_io_write: bool,

    netstat: NetworkStat,
}

impl ProcessStat {
    pub fn get_netstat(&self) -> &NetworkStat {
        &self.netstat
    }

    pub fn has_timestamp(&self) -> bool {
        self.timestamp
    }
    pub fn has_total_system_cpu_time(&self) -> bool {
        self.total_system_cpu_time
    }
    pub fn has_total_user_cpu_time(&self) -> bool {
        self.total_user_cpu_time
    }
    pub fn has_total_cpu_time(&self) -> bool {
        self.total_cpu_time
    }
    pub fn has_total_rss(&self) -> bool {
        self.total_rss
    }
    pub fn has_total_vss(&self) -> bool {
        self.total_vss
    }
    pub fn has_total_swap(&self) -> bool {
        self.total_swap
    }
    pub fn has_total_io_read(&self) -> bool {
        self.total_io_read
    }
    pub fn has_total_io_write(&self) -> bool {
        self.total_io_write
    }
    pub fn has_total_block_io_read(&self) -> bool {
        self.total_block_io_read
    }
    pub fn has_total_block_io_write(&self) -> bool {
        self.total_block_io_write
    }
}

#[derive(Deserialize, Clone, Copy, Debug)]
pub struct ThreadStat {
    timestamp: bool,
    total_system_cpu_time: bool,
    total_user_cpu_time: bool,
    total_cpu_time: bool,
    total_io_read: bool,
    total_io_write: bool,
    total_block_io_read: bool,
    total_block_io_write: bool,
}

impl ThreadStat {
    pub fn has_timestamp(&self) -> bool {
        self.timestamp
    }
    pub fn has_total_system_cpu_time(&self) -> bool {
        self.total_system_cpu_time
    }
    pub fn has_total_user_cpu_time(&self) -> bool {
        self.total_user_cpu_time
    }
    pub fn has_total_cpu_time(&self) -> bool {
        self.total_cpu_time
    }
    pub fn has_total_io_read(&self) -> bool {
        self.total_io_read
    }
    pub fn has_total_io_write(&self) -> bool {
        self.total_io_write
    }
    pub fn has_total_block_io_read(&self) -> bool {
        self.total_block_io_read
    }
    pub fn has_total_block_io_write(&self) -> bool {
        self.total_block_io_write
    }
}

#[derive(Deserialize, Clone, Copy, Debug)]
pub struct Thread {
    tid: bool,
    pid: bool,
    real_tid: bool,
    real_pid: bool,

    stat: ThreadStat,
}

impl Thread {
    pub fn get_stat(&self) -> &ThreadStat {
        &self.stat
    }

    pub fn has_tid(&self) -> bool {
        self.tid
    }
    pub fn has_pid(&self) -> bool {
        self.pid
    }
    pub fn has_real_tid(&self) -> bool {
        self.real_tid
    }
    pub fn has_real_pid(&self) -> bool {
        self.real_pid
    }
}

#[derive(Deserialize, Clone, Copy, Debug)]
pub struct Process {
    pid: bool,
    parent_pid: bool,
    uid: bool,
    effective_uid: bool,
    saved_uid: bool,
    fs_uid: bool,
    gid: bool,
    effective_gid: bool,
    saved_gid: bool,
    fs_gid: bool,

    real_pid: bool,
    real_parent_pid: bool,
    real_uid: bool,
    real_effective_uid: bool,
    real_saved_uid: bool,
    real_fs_uid: bool,
    real_gid: bool,
    real_effective_gid: bool,
    real_saved_gid: bool,
    real_fs_gid: bool,
    exec_path: bool,
    command: bool,
    child_real_pid_list: bool,

    stat: ProcessStat,
    thread: Thread
}

impl Process {
    pub fn get_thread(&self) -> &Thread {
        &self.thread
    }
    pub fn has_pid(&self) -> bool {
        self.pid
    }
    pub fn has_parent_pid(&self) -> bool {
        self.parent_pid
    }
    pub fn has_uid(&self) -> bool {
        self.uid
    }
    pub fn has_effective_uid(&self) -> bool {
        self.effective_uid
    }
    pub fn has_saved_uid(&self) -> bool {
        self.saved_uid
    }
    pub fn has_fs_uid(&self) -> bool {
        self.fs_uid
    }
    pub fn has_gid(&self) -> bool {
        self.gid
    }
    pub fn has_effective_gid(&self) -> bool {
        self.effective_gid
    }
    pub fn has_saved_gid(&self) -> bool {
        self.saved_gid
    }
    pub fn has_fs_gid(&self) -> bool {
        self.fs_gid
    }
    pub fn has_real_pid(&self) -> bool {
        self.real_pid
    }
    pub fn has_real_parent_pid(&self) -> bool {
        self.real_parent_pid
    }
    pub fn has_real_uid(&self) -> bool {
        self.real_uid
    }
    pub fn has_real_effective_uid(&self) -> bool {
        self.real_effective_uid
    }
    pub fn has_real_saved_uid(&self) -> bool {
        self.real_saved_uid
    }
    pub fn has_real_fs_uid(&self) -> bool {
        self.real_fs_uid
    }
    pub fn has_real_gid(&self) -> bool {
        self.real_gid
    }
    pub fn has_real_effective_gid(&self) -> bool {
        self.real_effective_gid
    }
    pub fn has_real_saved_gid(&self) -> bool {
        self.real_saved_gid
    }
    pub fn has_real_fs_gid(&self) -> bool {
        self.real_fs_gid
    }
    pub fn has_exec_path(&self) -> bool {
        self.exec_path
    }
    pub fn has_command(&self) -> bool {
        self.command
    }
    pub fn has_child_real_pid_list(&self) -> bool {
        self.child_real_pid_list
    }

    pub fn get_stat(&self) -> &ProcessStat {
        &self.stat
    }
}

#[derive(Deserialize, Clone, Copy, Debug)]
pub struct Filter {
    unix_timestamp: bool,
    network_rawstat: NetworkRawStat,
    process: Process,
}

impl Filter {
    pub fn has_unix_timestamp(&self) -> bool {
        self.unix_timestamp
    }
    pub fn get_network_rawstat(&self) -> &NetworkRawStat {
        &self.network_rawstat
    }
    pub fn get_process(&self) -> &Process {
        &self.process
    }
}
