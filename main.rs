mod NetworkStat;
mod Process;
mod common;
mod config;
mod netlink;
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
use crate::taskstat::{TaskStatsConnection, TaskStatsError};
use crate::NetworkStat::{NetworkRawStat, NetworkStatError};
use crate::Process::{Pid, ProcessError};

#[derive(Debug, Clone, Default, Serialize)]
pub struct ContainerStat {
    containerName: String,
    processes: Vec<Process::Process>,
}

impl ContainerStat {
    pub fn New(containerName: String) -> Self {
        Self {
            containerName,
            processes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TotalStat {
    containerStats: Vec<ContainerStat>,
    networkRawStat: NetworkRawStat,
}

impl TotalStat {
    pub fn New() -> Self {
        Self {
            containerStats: Vec::new(),
            networkRawStat: NetworkRawStat::New(),
        }
    }
}

fn GetProcessesStats(
    realPidList: &[Pid],
    taskStatsConnection: &mut TaskStatsConnection,
    networkRawStat: &mut NetworkRawStat,
) -> Result<Vec<Process::Process>, DaemonError> {
    let mut processes = Vec::new();

    for currentRealPid in realPidList {
        if let Ok(mut newProcess) = Process::GetRealProcess(currentRealPid) {
            if newProcess
                .BuildProcessTree(taskStatsConnection, networkRawStat)
                .is_ok()
            {
                processes.push(newProcess);
            }
        }
    }

    Ok(processes)
}

fn ListenThread() -> Result<(), DaemonError> {
    // create new taskstat connection
    let mut taskStatsConnection = TaskStatsConnection::New()?;

    // create socket
    let listener = TcpListener::bind(&config::GetGlobalConfig()?.ListenAddress())?;

    // listen for connection
    loop {
        match listener.accept() {
            Ok((mut stream, mut _peerAddr)) => {
                let mut totalStat = TotalStat::New();

                // get network raw stat
                totalStat.networkRawStat = NetworkStat::GetNetworkRawStat()?;

                // get global config
                let globalConfig = config::GetGlobalConfig().unwrap();

                // for each monitor target
                'monitorLoop: for monitorTarget in &globalConfig.MonitorTargets() {
                    // get needed process list
                    let realPidList = if monitorTarget.containerName != "/" {
                        let mut result = Vec::new();

                        // get all process belong to that container
                        let commandOutput = match Command::new("docker")
                            .args(["top", &monitorTarget.containerName])
                            .output()
                        {
                            Ok(output) => output,
                            Err(_) => continue,
                        };

                        let lines: Vec<&str> = std::str::from_utf8(&commandOutput.stdout)
                            .unwrap()
                            .lines()
                            .skip(1)
                            .collect::<Vec<&str>>();

                        for line in lines {
                            // get that process pid
                            let realPid = Pid::New(
                                line.split_whitespace().collect::<Vec<&str>>()[1].parse()?,
                            );

                            if globalConfig.IsOldKernel() {
                                result.push(realPid);
                                continue;
                            }

                            // get pid inside namespace
                            let statusFileContent =
                                match fs::read_to_string(format!("/proc/{}/status", realPid)) {
                                    Ok(content) => content,
                                    Err(_) => continue 'monitorLoop,
                                };

                            let contentLines: Vec<&str> = statusFileContent.lines().collect();

                            // get pid
                            let pids = contentLines[12].split_whitespace().collect::<Vec<&str>>();
                            let pid = Pid::try_from(pids[pids.len() - 1]).unwrap();

                            // check if pid is needed
                            if monitorTarget.pidList.contains(&pid) {
                                result.push(realPid);
                            }
                        }

                        result
                    } else {
                        monitorTarget.pidList.clone()
                    };

                    // get stats
                    match GetProcessesStats(
                        &realPidList,
                        &mut taskStatsConnection,
                        &mut totalStat.networkRawStat,
                    ) {
                        Ok(stats) => {
                            // add stat to new container stat
                            let containerStat = ContainerStat {
                                containerName: monitorTarget.containerName.clone(),
                                processes: stats,
                            };

                            totalStat.containerStats.push(containerStat);
                        }
                        Err(err) => {
                            println!("error: {}", err);
                            continue;
                        }
                    }
                }

                // clean up network raw stat
                totalStat.networkRawStat.RemoveUsedUniConnectionStats();

                // return result
                if config::GetGlobalConfig().unwrap().PrintPrettyOutput() {
                    let _ =
                        stream.write(serde_json::to_string_pretty(&totalStat).unwrap().as_bytes());
                } else {
                    let _ = stream.write(serde_json::to_string(&totalStat).unwrap().as_bytes());
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
        return Err(DaemonError::NO_CONFIG_PATH);
    }

    config::InitGlobalConfig(&env::args().nth(1).unwrap())?;

    // init network capture
    NetworkStat::InitNetworkStatCapture()?;

    // init listen thread
    let listenThread = thread::spawn(|| ListenThread());

    // wait forever
    match listenThread.join() {
        Err(listenThreadError) => return Err(DaemonError::LISTEN_THREAD_ERROR(listenThreadError)),
        _ => (),
    }

    Err(DaemonError::UNIMPLEMENTED_ERROR)
}

#[derive(Debug)]
pub enum DaemonError {
    NETWROK_STAT_ERROR(NetworkStatError),
    TASKSTATS_ERROR(TaskStatsError),
    IO_ERROR(io::Error),
    NO_CONFIG_PATH,
    CONFIG_ERROR(ConfigError),
    PROCESS_ERROR(ProcessError),
    LISTEN_THREAD_ERROR(Box<dyn Any + Send>),
    PARSE_INT_ERROR(std::num::ParseIntError),
    UNIMPLEMENTED_ERROR,
}

impl std::error::Error for DaemonError {}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let result = match self {
            Self::NETWROK_STAT_ERROR(networkStatError) => {
                String::from(format!("Network stat error: {}", networkStatError))
            }
            Self::TASKSTATS_ERROR(taskStatsError) => {
                String::from(format!("Taskstat error: {}", taskStatsError))
            }
            Self::IO_ERROR(ioError) => String::from(format!("IO error: {}", ioError)),
            Self::NO_CONFIG_PATH => String::from("No config path"),
            Self::CONFIG_ERROR(configError) => {
                String::from(format!("Config error: {}", configError))
            }
            Self::PROCESS_ERROR(processError) => {
                String::from(format!("Process error: {}", processError))
            }
            Self::LISTEN_THREAD_ERROR(listenThreadError) => {
                String::from(format!("Listen thread error: {:?}", listenThreadError))
            }
            Self::PARSE_INT_ERROR(error) => String::from(format!("Parse integer error: {}", error)),
            Self::UNIMPLEMENTED_ERROR => String::from("This error is not implemented"),
        };

        write!(f, "{}", result)
    }
}

impl From<NetworkStatError> for DaemonError {
    fn from(error: NetworkStatError) -> Self {
        Self::NETWROK_STAT_ERROR(error)
    }
}

impl From<TaskStatsError> for DaemonError {
    fn from(error: TaskStatsError) -> Self {
        Self::TASKSTATS_ERROR(error)
    }
}

impl From<io::Error> for DaemonError {
    fn from(error: io::Error) -> Self {
        Self::IO_ERROR(error)
    }
}

impl From<ConfigError> for DaemonError {
    fn from(error: ConfigError) -> Self {
        Self::CONFIG_ERROR(error)
    }
}

impl From<ProcessError> for DaemonError {
    fn from(error: ProcessError) -> Self {
        Self::PROCESS_ERROR(error)
    }
}

impl From<std::num::ParseIntError> for DaemonError {
    fn from(error: std::num::ParseIntError) -> Self {
        Self::PARSE_INT_ERROR(error)
    }
}
