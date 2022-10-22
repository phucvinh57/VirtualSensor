mod common;
mod config;
mod netlink;
mod network_stat;
mod process;
mod taskstat;

use std::any::Any;
use std::convert::TryFrom;
use std::fs;
use std::io::Write;
use std::net::TcpListener;
use std::process::Command;
use std::thread;
use std::{env, fmt, io};

#[macro_use]
extern crate lazy_static;

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
}

impl TotalStat {
    pub fn new() -> Self {
        Self {
            container_stats: Vec::new(),
            network_rawstat: NetworkRawStat::new(),
        }
    }
}

// TODO
fn get_processes_stats(
    real_pid_list: &[Pid],
    taskstats_conn: &mut TaskStatsConnection,
    net_rawstat: &mut NetworkRawStat,
) -> Result<Vec<process::Process>, DaemonError> {
    let mut processes = Vec::new();

    for curr_real_pid in real_pid_list {
        if let Ok(mut proc) = process::get_real_proc(curr_real_pid) {
            if proc
                .build_proc_tree(taskstats_conn, net_rawstat)
                .is_ok()
            {
                processes.push(proc);
            }
        }
    }

    Ok(processes)
}

fn listen_thread() -> Result<(), DaemonError> {
    // create new taskstat connection
    let mut taskstats_conn = TaskStatsConnection::new()?;

    // create socket
    let listener = TcpListener::bind(&config::get_glob_conf()?.get_listen_addr())?;

    // listen for connection
    loop {
        match listener.accept() {
            Ok((mut stream, mut _peer_addr)) => {
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
                            let real_pid = Pid::new(
                                line.split_whitespace().collect::<Vec<&str>>()[1].parse()?,
                            );

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
                        Ok(stats) => {
                            // add stat to new container stat
                            let container_stat = ContainerStat {
                                container_name: monitor_target.container_name.clone(),
                                processes: stats,
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
                    .remove_used_uni_connection_stats();

                // return result
                if config::get_glob_conf().unwrap().is_print_pretty_output() {
                    let _ = stream.write(
                        serde_json::to_string_pretty(&total_stat)
                            .unwrap()
                            .as_bytes(),
                    );
                } else {
                    let _ = stream.write(serde_json::to_string(&total_stat).unwrap().as_bytes());
                }
            }
            Err(err) => {
                println!("Network err: {}", err);
            }
        }
    }
}

fn main() -> Result<(), DaemonError> {
    // init config
    if env::args().len() != 2 {
        println!("Usage: ./daemon [config path]");
        return Err(DaemonError::NoConfigPath);
    }

    config::init_glob_conf(&env::args().nth(1).unwrap())?;

    // init network capture
    network_stat::init_network_stat_capture()?;

    // init listen thread
    let listen_thread = thread::spawn(|| listen_thread());

    // wait forever
    match listen_thread.join() {
        Err(listen_thread_err) => return Err(DaemonError::ListenThreadErr(listen_thread_err)),
        _ => (),
    }

    Err(DaemonError::UnimplementedErr)
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
    UnimplementedErr,
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
            Self::UnimplementedErr => String::from("This error is not implemented"),
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
