use serde::Deserialize;

#[allow(unused)]
#[derive(Deserialize, Clone, Copy, Debug)]
struct InterfaceRawStat {
    iname: bool,
    description: bool,
    uni_connection_stats: bool,
}

#[allow(unused)]
#[derive(Deserialize, Clone, Copy, Debug)]
struct NetworkRawStat {
    interface_rawstat: InterfaceRawStat,
}

#[allow(unused)]
#[derive(Deserialize, Clone, Copy, Debug)]
struct InterfaceStat {
    iname: bool,
    packet_sent: bool,
    packet_recv: bool,
    total_data_sent: bool,
    total_data_recv: bool,
    real_data_sent: bool,
    real_data_recv: bool,
    connection_stats: bool,
}

#[allow(unused)]
#[derive(Deserialize, Clone, Copy, Debug)]
struct NetStat {
    pack_sent: bool,
    pack_recv: bool,
    total_data_sent: bool,
    total_data_recv: bool,
    real_data_sent: bool,
    real_data_recv: bool,
}

#[allow(unused)]
#[derive(Deserialize, Clone, Copy, Debug)]
struct ProcessStat {
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

#[allow(unused)]
#[derive(Deserialize, Clone, Copy, Debug)]
struct ThreadStat {
    timestamp: bool,
    total_system_cpu_time: bool,
    total_user_cpu_time: bool,
    total_cpu_time: bool,
    total_io_read: bool,
    total_io_write: bool,
    total_block_io_read: bool,
    total_block_io_write: bool,
}

#[allow(unused)]
#[derive(Deserialize, Clone, Copy, Debug)]
struct Thread {
    tid: bool,
    pid: bool,
    real_tid: bool,
    real_pid: bool,
}

#[allow(unused)]
#[derive(Deserialize, Clone, Copy, Debug)]
struct Process {
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

#[allow(unused)]
#[derive(Deserialize, Clone, Copy, Debug)]
pub struct Filter {
    unix_timestamp: bool,
    network_rawstat: NetworkRawStat,
    process: Process
    
}
