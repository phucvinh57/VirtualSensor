use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use config_file::{ConfigFileError, FromConfigFile};
use serde::{Deserialize, Deserializer};

use crate::process::Pid;

static mut GLOBAL_CONFIG: Option<Arc<DaemonConfig>> = None;

#[derive(Debug, Clone, Deserialize)]
pub struct MonitorTarget {
    pub container_name: String,
    pub pid_list: Vec<Pid>,
}

// TODO: add fields to config struc
#[derive(Debug, Clone, Deserialize)]
pub struct DaemonConfig {
    old_kernel: bool,

    listen_addr: String,
    capture_size_limit: usize,
    #[serde(deserialize_with = "nanosecs_to_duration")]
    control_command_receive_timeout: Duration,
    #[serde(deserialize_with = "nanosecs_to_duration")]
    capture_thread_receive_timeout: Duration,
    print_pretty_output: bool,

    monitor_targets: Vec<MonitorTarget>,
}

impl DaemonConfig {
    pub fn is_old_kernel(&self) -> bool {
        self.old_kernel
    }
    pub fn get_listen_addr(&self) -> String {
        self.listen_addr.clone()
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
    pub fn is_print_pretty_output(&self) -> bool {
        self.print_pretty_output
    }
    pub fn get_monitor_targets(&self) -> Vec<MonitorTarget> {
        self.monitor_targets.clone()
    }
}

fn nanosecs_to_duration<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
    Ok(Duration::from_nanos(Deserialize::deserialize(
        deserializer,
    )?))
}

pub fn init_glob_conf(conf_path: &str) -> Result<(), ConfigError> {
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
