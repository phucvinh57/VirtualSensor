mod common;
mod config;
mod netlink;
mod network_stat;
mod process;
mod taskstat;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::{task, time};

use std::any::Any;
use std::convert::TryFrom;
use std::fs;
use std::process::Command;
use std::{env, fmt, io};

#[macro_use]
extern crate lazy_static;

use process::iterate_proc_tree;
use serde::Serialize;
use serde_json;

use crate::config::ConfigError;
use crate::network_stat::{NetworkRawStat, NetworkStatError};
use crate::process::{Pid, ProcessError};
use crate::taskstat::{TaskStatsConnection, TaskStatsError};

#[derive(Debug, Clone, Default, Serialize)]
pub struct ContainerStat {
    container_name: String,
    processes: Vec<process::Process>,
}

impl ContainerStat {
    pub fn new(container_name: String) -> Self {
        Self {
            container_name,
            processes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TotalStat {
    container_stats: Vec<ContainerStat>,
    network_rawstat: NetworkRawStat,
    timestamp: Duration,
}

impl TotalStat {
    pub fn new() -> Self {
        let start: SystemTime = SystemTime::now();
        let timestamp: Duration = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");

        Self {
            container_stats: Vec::new(),
            network_rawstat: NetworkRawStat::new(),
            timestamp,
        }
    }
}

// TODO
fn get_processes_stats(
    real_pid_list: &[Pid],
    taskstats_conn: &TaskStatsConnection,
    net_rawstat: &mut NetworkRawStat,
) -> Result<Vec<process::Process>, DaemonError> {
    let mut processes_list = Vec::new();

    for curr_real_pid in real_pid_list {
        if let Ok(proc) = process::get_real_proc(curr_real_pid, taskstats_conn, net_rawstat) {
            iterate_proc_tree(&proc, &mut processes_list, taskstats_conn, net_rawstat);
        }
    }

    Ok(processes_list)
}

async fn read_monitored_data() -> Result<(), DaemonError> {
    // create new taskstat connection
    let mut taskstats_conn = TaskStatsConnection::new()?;

    // listen for connection

    let mut total_stat = TotalStat::new();

    // get network raw stat
    total_stat.network_rawstat = network_stat::get_network_rawstat()?;

    // get global config
    let glob_conf = config::get_glob_conf().unwrap();

    // for each monitor target
    'monitorLoop: for monitor_target in &glob_conf.get_monitor_targets() {
        // get needed process list
        let real_pid_list = if monitor_target.container_name != "/" {
            let mut result = Vec::new();
            // get all process belong to that container
            let cmd_output = match Command::new("docker")
                .args(["top", &monitor_target.container_name])
                .output()
            {
                Ok(output) => output,
                Err(_) => continue,
            };

            let lines: Vec<&str> = std::str::from_utf8(&cmd_output.stdout)
                .unwrap()
                .lines()
                .skip(1)
                .collect::<Vec<&str>>();

            for line in lines {
                // get that process pid
                let real_pid = Pid::new(line.split_whitespace().collect::<Vec<&str>>()[1].parse()?);

                if glob_conf.is_old_kernel() {
                    result.push(real_pid);
                    continue;
                }

                // get pid inside namespace
                let file_status_content =
                    match fs::read_to_string(format!("/proc/{}/status", real_pid)) {
                        Ok(content) => content,
                        Err(_) => continue 'monitorLoop,
                    };

                let content_lines: Vec<&str> = file_status_content.lines().collect();

                // get pid
                let pids = content_lines[12].split_whitespace().collect::<Vec<&str>>();
                let pid = Pid::try_from(pids[pids.len() - 1]).unwrap();

                // check if pid is needed
                if monitor_target.pid_list.contains(&pid) {
                    result.push(real_pid);
                }
            }

            result
        } else {
            monitor_target.pid_list.clone()
        };

        // get stats
        match get_processes_stats(
            &real_pid_list,
            &mut taskstats_conn,
            &mut total_stat.network_rawstat,
        ) {
            Ok(processes) => {
                // add stat to new container stat
                let container_stat = ContainerStat {
                    container_name: monitor_target.container_name.clone(),
                    processes,
                };

                total_stat.container_stats.push(container_stat);
            }
            Err(err) => {
                println!("error: {}", err);
                continue;
            }
        }
    }

    // clean up network raw stat
    total_stat
        .network_rawstat
        .remove_unused_uni_connection_stats();

    // return result
    if config::get_glob_conf().unwrap().is_print_pretty_output() {
        let _ = fs::write(
            "test.json",
            serde_json::to_string_pretty(&total_stat)
                .unwrap()
                .as_bytes(),
        );
    } else {
        let _ = fs::write(
            "test.json",
            serde_json::to_string(&total_stat).unwrap().as_bytes(),
        );
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), DaemonError> {
    // init config
    if env::args().len() != 2 {
        println!("Usage: ./daemon [config path]");
        return Err(DaemonError::NoConfigPath);
    }

    config::fetch_glob_conf(&env::args().nth(1).unwrap())?;

    // init network capture
    network_stat::init_network_stat_capture()?;

    let glob_conf = config::get_glob_conf().unwrap();

    let forever = task::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(
            glob_conf.get_publish_msg_interval(),
        ));

        loop {
            interval.tick().await;
            let _ = read_monitored_data().await;
        }
    });

    let _ = forever.await;

    Err(DaemonError::UnknownErr)
}

#[derive(Debug)]
pub enum DaemonError {
    NetworkStatErr(NetworkStatError),
    TaskstatsErr(TaskStatsError),
    IOErr(io::Error),
    NoConfigPath,
    ConfigErr(ConfigError),
    ProcessErr(ProcessError),
    ListenThreadErr(Box<dyn Any + Send>),
    ParseIntErr(std::num::ParseIntError),
    UnknownErr,
}

impl std::error::Error for DaemonError {}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let result = match self {
            Self::NetworkStatErr(netstat_err) => {
                String::from(format!("Network stat error: {}", netstat_err))
            }
            Self::TaskstatsErr(taskstats_err) => {
                String::from(format!("Taskstat error: {}", taskstats_err))
            }
            Self::IOErr(io_err) => String::from(format!("IO error: {}", io_err)),
            Self::NoConfigPath => String::from("No config path"),
            Self::ConfigErr(conf_err) => String::from(format!("Config error: {}", conf_err)),
            Self::ProcessErr(proc_err) => String::from(format!("Process error: {}", proc_err)),
            Self::ListenThreadErr(listen_thread_err) => {
                String::from(format!("Listen thread error: {:?}", listen_thread_err))
            }
            Self::ParseIntErr(error) => String::from(format!("Parse integer error: {}", error)),
            Self::UnknownErr => String::from("This error is not implemented"),
        };

        write!(f, "{}", result)
    }
}

impl From<NetworkStatError> for DaemonError {
    fn from(error: NetworkStatError) -> Self {
        Self::NetworkStatErr(error)
    }
}

impl From<TaskStatsError> for DaemonError {
    fn from(error: TaskStatsError) -> Self {
        Self::TaskstatsErr(error)
    }
}

impl From<io::Error> for DaemonError {
    fn from(error: io::Error) -> Self {
        Self::IOErr(error)
    }
}

impl From<ConfigError> for DaemonError {
    fn from(error: ConfigError) -> Self {
        Self::ConfigErr(error)
    }
}

impl From<ProcessError> for DaemonError {
    fn from(error: ProcessError) -> Self {
        Self::ProcessErr(error)
    }
}

impl From<std::num::ParseIntError> for DaemonError {
    fn from(error: std::num::ParseIntError) -> Self {
        Self::ParseIntErr(error)
    }
}
