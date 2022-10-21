use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use config_file::{ConfigFileError, FromConfigFile};
use serde::{Deserialize, Deserializer};

use crate::Process::Pid;

static mut globalConfig: Option<Arc<DaemonConfig>> = None;

#[derive(Debug, Clone, Deserialize)]
pub struct MonitorTarget {
    pub containerName: String,
    pub pidList: Vec<Pid>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DaemonConfig {
    oldKernel: bool,

    listenAddress: String,
    captureSizeLimit: usize,
    #[serde(deserialize_with = "NanoSecondsToDuration")]
    controlCommandReceiveTimeout: Duration,
    #[serde(deserialize_with = "NanoSecondsToDuration")]
    captureThreadReceiveTimeout: Duration,
    printPrettyOutput: bool,

    monitorTargets: Vec<MonitorTarget>,
}

impl DaemonConfig {
    pub fn IsOldKernel(&self) -> bool {
        self.oldKernel
    }
    pub fn ListenAddress(&self) -> String {
        self.listenAddress.clone()
    }
    pub fn CaptureSizeLimit(&self) -> usize {
        self.captureSizeLimit
    }
    pub fn ControlCommandReceiveTimeout(&self) -> Duration {
        self.controlCommandReceiveTimeout
    }
    pub fn CaptureThreadReceiveTimeout(&self) -> Duration {
        self.captureThreadReceiveTimeout
    }
    pub fn PrintPrettyOutput(&self) -> bool {
        self.printPrettyOutput
    }
    pub fn MonitorTargets(&self) -> Vec<MonitorTarget> {
        self.monitorTargets.clone()
    }
}

fn NanoSecondsToDuration<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
    Ok(Duration::from_nanos(Deserialize::deserialize(
        deserializer,
    )?))
}

pub fn InitGlobalConfig(configPath: &str) -> Result<(), ConfigError> {
    let config = DaemonConfig::from_config_file(configPath)?;

    unsafe {
        globalConfig = Some(Arc::new(config));
    }

    Ok(())
}

pub fn GetGlobalConfig() -> Result<Arc<DaemonConfig>, ConfigError> {
    unsafe {
        match &globalConfig {
            Some(config) => Ok(Arc::clone(config)),
            None => Err(ConfigError::UNINITIALIZED_CONFIG),
        }
    }
}

#[derive(Debug)]
pub enum ConfigError {
    LOAD_CONFIG_ERROR(ConfigFileError),
    UNINITIALIZED_CONFIG,
}

impl std::error::Error for ConfigError {}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let result = match self {
            Self::LOAD_CONFIG_ERROR(configError) => {
                String::from(format!("Load config error: {}", configError))
            }
            Self::UNINITIALIZED_CONFIG => String::from("Uninitialized config"),
        };

        write!(f, "{}", result)
    }
}

impl From<ConfigFileError> for ConfigError {
    fn from(error: ConfigFileError) -> Self {
        Self::LOAD_CONFIG_ERROR(error)
    }
}
