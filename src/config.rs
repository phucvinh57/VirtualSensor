pub mod filter;

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use config_file::{ConfigFileError, FromConfigFile};
use serde::{Deserialize, Deserializer};

use crate::process::Pid;

use filter::Filter;

pub static mut GLOBAL_CONFIG: Option<Arc<DaemonConfig>> = None;

#[derive(Debug, Clone, Deserialize)]
pub struct MonitorTarget {
    pub container_name: String,
    pub pid_list: Vec<Pid>,
}

// TODO: add fields to config struct
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

    filter: Filter
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

    pub fn get_filter(&self) -> Filter {
        self.filter
    }
}

fn duration_to_nanosecs<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
    Ok(Duration::from_nanos(Deserialize::deserialize(
        deserializer,
    )?))
}

pub fn fetch_glob_conf(conf_path: &str) -> Result<(), ConfigError> {
    let config = DaemonConfig::from_config_file(conf_path)?;

    unsafe {
        GLOBAL_CONFIG = Some(Arc::new(config));
    }

    Ok(())
}

// TODO (get from file instead of from init_glob_conf result)
pub fn get_glob_conf() -> Result<Arc<DaemonConfig>, ConfigError> {
    unsafe {
        match &GLOBAL_CONFIG {
            Some(config) => Ok(Arc::clone(config)),
            None => Err(ConfigError::UninitializedConfig),
        }
    }
}

#[derive(Debug)]
pub enum ConfigError {
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
        };

        write!(f, "{}", result)
    }
}

impl From<ConfigFileError> for ConfigError {
    fn from(error: ConfigFileError) -> Self {
        Self::LoadConfigErr(error)
    }
}
