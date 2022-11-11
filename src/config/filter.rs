use serde::Deserialize;

#[derive(Deserialize, Clone, Copy, Debug)]
pub struct InterfaceRawStat {
    iname: bool,
    description: bool,
    uni_connection_stats: bool,
}

#[derive(Deserialize, Clone, Copy, Debug)]
pub struct NetworkRawStat {
    interface_rawstat: InterfaceRawStat,
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

#[derive(Deserialize, Clone, Copy, Debug)]
pub struct NetStat {
    pack_sent: bool,
    pack_recv: bool,
    total_data_sent: bool,
    total_data_recv: bool,
    real_data_sent: bool,
    real_data_recv: bool,
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

#[derive(Deserialize, Clone, Copy, Debug)]
pub struct Thread {
    tid: bool,
    pid: bool,
    real_tid: bool,
    real_pid: bool,
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
    pub fn get_network_rawstat(&self) -> NetworkRawStat {
        self.network_rawstat
    }
}
