pub mod filter;

use std::sync::{Arc, RwLock};
use std::time::Duration;
use std::{fmt, fs};

use config_file::{ConfigFileError, FromConfigFile};
use serde::{Deserialize, Deserializer};
use serde_json;
use toml;

// use crate::common::Timestamp;
use crate::process::Pid;

use filter::Filter;

pub static mut GLOBAL_CONFIG: Option<Arc<RwLock<DaemonConfig>>> = None;

#[derive(Debug, Clone, Deserialize)]
pub struct MonitorTarget {
    pub container_name: String,
    pub pid_list: Vec<Pid>,
}
// #[derive(Deserialize)]
// pub struct SensorInfo {
//     id: String,
//     name: String,
//     cluster: String,

//     #[serde(skip_serializing_if = "Option::is_none")]
//     active: Option<bool>,
//     updatedAt: Timestamp,

//     config: DaemonConfig
// }

// impl SensorInfo {

// }

#[derive(Deserialize)]
pub struct DaemonConfig {
    old_kernel: bool,

    capture_size_limit: usize,

    #[serde(deserialize_with = "duration_to_nanosecs")]
    control_command_receive_timeout: Duration,

    #[serde(deserialize_with = "duration_to_nanosecs")]
    capture_thread_receive_timeout: Duration,

    dev_flag: bool,
    publish_msg_interval: u64,
    monitor_targets: Vec<MonitorTarget>,

    msg_chunk_size: Option<usize>,

    filter: Filter,
}

impl DaemonConfig {
    pub fn is_old_kernel(&self) -> bool {
        self.old_kernel
    }
    pub fn get_capture_size_limit(&self) -> usize {
        self.capture_size_limit
    }
    pub fn get_control_command_receive_timeout(&self) -> Duration {
        self.control_command_receive_timeout
    }
    pub fn get_capture_thread_receive_timeout(&self) -> Duration {
        self.capture_thread_receive_timeout
    }
    pub fn get_dev_flag(&self) -> bool {
        self.dev_flag
    }
    pub fn get_monitor_targets(&self) -> Vec<MonitorTarget> {
        self.monitor_targets.clone()
    }
    pub fn get_publish_msg_interval(&self) -> u64 {
        self.publish_msg_interval
    }
    pub fn get_filter(&self) -> &Filter {
        &self.filter
    }
    pub fn get_message_chunk_size(&self) -> Option<usize> {
        self.msg_chunk_size
    }
}

fn duration_to_nanosecs<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
    Ok(Duration::from_nanos(Deserialize::deserialize(
        deserializer,
    )?))
}

pub fn init_glob_conf(conf_path: &str) -> Result<(), ConfigError> {
    let config = DaemonConfig::from_config_file(conf_path)?;

    unsafe {
        GLOBAL_CONFIG = Some(Arc::new(RwLock::new(config)));
    }

    Ok(())
}

// Conf_text js JSON formatted
pub fn update_glob_conf(conf_path: &str, conf_text: &str) -> Result<(), ConfigError> {
    let binding = get_glob_conf().unwrap();
    let write = binding.write();
    match write {
        Ok(mut glob_conf) => {
            let config_in_json: DaemonConfig = serde_json::from_str(conf_text).unwrap();
            *glob_conf = config_in_json;
        
            let config_in_toml: toml::Value = serde_json::from_str(conf_text).unwrap();
            let _ = fs::write(conf_path, config_in_toml.to_string());
            Ok(())
        },
        Err(_) => Err(ConfigError::IncorrectConfig) 
    }
}

// TODO (get from file instead of from init_glob_conf result)
pub fn get_glob_conf() -> Result<Arc<RwLock<DaemonConfig>>, ConfigError> {
    unsafe {
        match &GLOBAL_CONFIG {
            Some(config) => Ok(Arc::clone(config)),
            None => Err(ConfigError::UninitializedConfig),
        }
    }
}

pub fn has_unix_timestamp<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf.get_filter().has_unix_timestamp()
}
pub fn has_irawstat_iname<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf
        .get_filter()
        .get_network_rawstat()
        .get_irawstat()
        .has_iname()
}
pub fn has_irawstat_description<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf
        .get_filter()
        .get_network_rawstat()
        .get_irawstat()
        .has_description()
}
pub fn has_irawstat_uni_connection_stats<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf
        .get_filter()
        .get_network_rawstat()
        .get_irawstat()
        .has_uni_connection_stats()
}
pub fn has_process_pid<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf.get_filter().get_process().has_pid()
}
pub fn has_process_parent_pid<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf.get_filter().get_process().has_parent_pid()
}
pub fn has_process_uid<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf.get_filter().get_process().has_uid()
}
pub fn has_process_effective_uid<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf.get_filter().get_process().has_effective_uid()
}
pub fn has_process_saved_uid<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf.get_filter().get_process().has_saved_uid()
}
pub fn has_process_fs_uid<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf.get_filter().get_process().has_fs_uid()
}
pub fn has_process_gid<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf.get_filter().get_process().has_gid()
}
pub fn has_process_effective_gid<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf.get_filter().get_process().has_effective_gid()
}
pub fn has_process_saved_gid<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf.get_filter().get_process().has_saved_gid()
}
pub fn has_process_fs_gid<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf.get_filter().get_process().has_fs_gid()
}
pub fn has_process_real_pid<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf.get_filter().get_process().has_real_pid()
}
pub fn has_process_real_parent_pid<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf.get_filter().get_process().has_real_parent_pid()
}
pub fn has_process_real_uid<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf.get_filter().get_process().has_real_uid()
}
pub fn has_process_real_effective_uid<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf
        .get_filter()
        .get_process()
        .has_real_effective_uid()
}
pub fn has_process_real_saved_uid<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf.get_filter().get_process().has_real_saved_uid()
}
pub fn has_process_real_fs_uid<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf.get_filter().get_process().has_real_fs_uid()
}
pub fn has_process_real_gid<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf.get_filter().get_process().has_real_gid()
}
pub fn has_process_real_effective_gid<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf
        .get_filter()
        .get_process()
        .has_real_effective_gid()
}
pub fn has_process_real_saved_gid<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf.get_filter().get_process().has_real_saved_gid()
}
pub fn has_process_real_fs_gid<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf.get_filter().get_process().has_real_fs_gid()
}
pub fn has_process_exec_path<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf.get_filter().get_process().has_exec_path()
}
pub fn has_process_command<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf.get_filter().get_process().has_command()
}
pub fn has_process_child_real_pid_list<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf
        .get_filter()
        .get_process()
        .has_child_real_pid_list()
}

pub fn has_process_stat_timestamp<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf
        .get_filter()
        .get_process()
        .get_stat()
        .has_timestamp()
}
pub fn has_process_stat_total_system_cpu_time<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf
        .get_filter()
        .get_process()
        .get_stat()
        .has_total_system_cpu_time()
}
pub fn has_process_stat_total_user_cpu_time<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf
        .get_filter()
        .get_process()
        .get_stat()
        .has_total_user_cpu_time()
}
pub fn has_process_stat_total_cpu_time<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf
        .get_filter()
        .get_process()
        .get_stat()
        .has_total_cpu_time()
}
pub fn has_process_stat_total_rss<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf
        .get_filter()
        .get_process()
        .get_stat()
        .has_total_rss()
}
pub fn has_process_stat_total_vss<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf
        .get_filter()
        .get_process()
        .get_stat()
        .has_total_vss()
}
pub fn has_process_stat_total_swap<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf
        .get_filter()
        .get_process()
        .get_stat()
        .has_total_swap()
}
pub fn has_process_stat_total_io_read<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf
        .get_filter()
        .get_process()
        .get_stat()
        .has_total_io_read()
}
pub fn has_process_stat_total_io_write<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf
        .get_filter()
        .get_process()
        .get_stat()
        .has_total_io_write()
}
pub fn has_process_stat_total_block_io_read<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf
        .get_filter()
        .get_process()
        .get_stat()
        .has_total_block_io_read()
}
pub fn has_process_stat_total_block_io_write<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf
        .get_filter()
        .get_process()
        .get_stat()
        .has_total_block_io_write()
}

pub fn has_process_netstat_pack_sent<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf
        .get_filter()
        .get_process()
        .get_stat()
        .get_netstat()
        .has_pack_sent()
}
pub fn has_process_netstat_pack_recv<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf
        .get_filter()
        .get_process()
        .get_stat()
        .get_netstat()
        .has_pack_recv()
}
pub fn has_process_netstat_total_data_sent<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf
        .get_filter()
        .get_process()
        .get_stat()
        .get_netstat()
        .has_total_data_sent()
}
pub fn has_process_netstat_total_data_recv<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf
        .get_filter()
        .get_process()
        .get_stat()
        .get_netstat()
        .has_total_data_recv()
}
pub fn has_process_netstat_real_data_sent<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf
        .get_filter()
        .get_process()
        .get_stat()
        .get_netstat()
        .has_real_data_sent()
}
pub fn has_process_netstat_real_data_recv<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf
        .get_filter()
        .get_process()
        .get_stat()
        .get_netstat()
        .has_real_data_recv()
}

pub fn has_process_istat_iname<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf
        .get_filter()
        .get_process()
        .get_stat()
        .get_netstat()
        .get_interface_stat()
        .has_iname()
}
pub fn has_process_istat_packet_sent<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf
        .get_filter()
        .get_process()
        .get_stat()
        .get_netstat()
        .get_interface_stat()
        .has_packet_sent()
}
pub fn has_process_istat_packet_recv<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf
        .get_filter()
        .get_process()
        .get_stat()
        .get_netstat()
        .get_interface_stat()
        .has_packet_recv()
}
pub fn has_process_istat_total_data_sent<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf
        .get_filter()
        .get_process()
        .get_stat()
        .get_netstat()
        .get_interface_stat()
        .has_total_data_sent()
}
pub fn has_process_istat_total_data_recv<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf
        .get_filter()
        .get_process()
        .get_stat()
        .get_netstat()
        .get_interface_stat()
        .has_total_data_recv()
}
pub fn has_process_istat_real_data_sent<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf
        .get_filter()
        .get_process()
        .get_stat()
        .get_netstat()
        .get_interface_stat()
        .has_real_data_sent()
}
pub fn has_process_istat_real_data_recv<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf
        .get_filter()
        .get_process()
        .get_stat()
        .get_netstat()
        .get_interface_stat()
        .has_real_data_recv()
}
pub fn has_process_istat_connection_stats<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf
        .get_filter()
        .get_process()
        .get_stat()
        .get_netstat()
        .get_interface_stat()
        .has_connection_stats()
}

pub fn has_thread_tid<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf.get_filter().get_process().get_thread().has_tid()
}

pub fn has_thread_pid<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf.get_filter().get_process().get_thread().has_pid()
}

pub fn has_thread_real_tid<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf
        .get_filter()
        .get_process()
        .get_thread()
        .has_real_tid()
}

pub fn has_thread_real_pid<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf
        .get_filter()
        .get_process()
        .get_thread()
        .has_real_pid()
}

pub fn has_thread_stat_timestamp<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf
        .get_filter()
        .get_process()
        .get_thread()
        .get_stat()
        .has_timestamp()
}
pub fn has_thread_stat_total_system_cpu_time<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf
        .get_filter()
        .get_process()
        .get_thread()
        .get_stat()
        .has_total_system_cpu_time()
}
pub fn has_thread_stat_total_user_cpu_time<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf
        .get_filter()
        .get_process()
        .get_thread()
        .get_stat()
        .has_total_user_cpu_time()
}
pub fn has_thread_stat_total_cpu_time<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf
        .get_filter()
        .get_process()
        .get_thread()
        .get_stat()
        .has_total_cpu_time()
}
pub fn has_thread_stat_total_io_read<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf
        .get_filter()
        .get_process()
        .get_thread()
        .get_stat()
        .has_total_io_read()
}
pub fn has_thread_stat_total_io_write<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf
        .get_filter()
        .get_process()
        .get_thread()
        .get_stat()
        .has_total_io_write()
}
pub fn has_thread_stat_total_block_io_read<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf
        .get_filter()
        .get_process()
        .get_thread()
        .get_stat()
        .has_total_block_io_read()
}
pub fn has_thread_stat_total_block_io_write<T>(_: &T) -> bool {
    let binding = get_glob_conf().unwrap();
    let glob_conf = binding.read().unwrap();
    !glob_conf
        .get_filter()
        .get_process()
        .get_thread()
        .get_stat()
        .has_total_block_io_write()
}

#[derive(Debug)]
pub enum ConfigError {
    IncorrectConfig,
    LoadConfigErr(ConfigFileError),
    UninitializedConfig,
}

impl std::error::Error for ConfigError {}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let result = match self {
            Self::LoadConfigErr(conf_err) => {
                String::from(format!("Load config error: {}", conf_err))
            }
            Self::UninitializedConfig => String::from("Uninitialized config"),
            Self::IncorrectConfig => String::from("Incorrect config!"),
        };

        write!(f, "{}", result)
    }
}

impl From<ConfigFileError> for ConfigError {
    fn from(error: ConfigFileError) -> Self {
        Self::LoadConfigErr(error)
    }
}
