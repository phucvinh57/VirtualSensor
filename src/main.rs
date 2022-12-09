mod common;
mod netlink;
mod network_stat;
mod process;
mod setting;
mod taskstat;
use kafka::producer::{Producer, Record, RequiredAcks};
use serde::Serialize;
use setting::update_glob_conf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::{task, time};

use dotenv::dotenv;
use std::any::Any;
use std::convert::TryFrom;
use std::fs;
use std::process::Command;
use std::{env, fmt, io};

#[macro_use]
extern crate lazy_static;

use process::iterate_proc_tree;

use crate::network_stat::{NetworkRawStat, NetworkStatError};
use crate::process::{Pid, ProcessError};
use crate::setting::ConfigError;
use crate::taskstat::{TaskStatsConnection, TaskStatsError};

#[derive(Debug, Clone, Default, Serialize)]
pub struct ContainerStat {
    container_name: String,
    processes: Vec<process::Process>,
}

#[derive(Serialize)]
pub struct MessageChunk {
    sensor_name: String,
    cluster_name: String,
    message: String,
}

impl MessageChunk {
    pub fn new(sensor_name: String, cluster_name: String, message: String) -> Self {
        Self {
            sensor_name,
            cluster_name,
            message,
        }
    }
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

    #[serde(skip_serializing_if = "setting::has_unix_timestamp")]
    unix_timestamp: u64, // in seconds
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
            unix_timestamp: timestamp.as_secs(),
        }
    }
}

fn get_processes_stats(
    real_pid_list: &[Pid],
    taskstats_conn: &TaskStatsConnection,
    net_rawstat: &mut NetworkRawStat,
) -> Result<Vec<process::Process>, DaemonError> {
    let mut processes_list = Vec::new();
    let mut iterated_pids = Vec::new();

    for curr_real_pid in real_pid_list {
        if iterated_pids.contains(curr_real_pid) {
            continue;
        }
        if let Ok(proc) = process::get_real_proc(curr_real_pid, taskstats_conn, net_rawstat) {
            iterate_proc_tree(
                &proc,
                &mut processes_list,
                &mut iterated_pids,
                taskstats_conn,
                net_rawstat,
            );
        }
    }

    Ok(processes_list)
}

async fn read_monitored_data(kafka_producer: &mut Option<Producer>) -> Result<(), DaemonError> {
    // create new taskstat connection
    let mut taskstats_conn = TaskStatsConnection::new()?;

    // listen for connection

    let mut total_stat = TotalStat::new();

    // get network raw stat
    total_stat.network_rawstat = network_stat::get_network_rawstat()?;

    // get global config
    let borrowing = setting::get_glob_conf()?;
    let glob_conf = borrowing.read().unwrap();

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

    let dev_flag = glob_conf.get_dev_flag();
    let message_chunk_size = glob_conf.get_message_chunk_size();
    let results_as_str = serde_json::to_string(&total_stat).unwrap();
    let messages = if let Some(size) = message_chunk_size {
        results_as_str
            .chars()
            .collect::<Vec<char>>()
            .chunks(size)
            .map(|c| c.iter().collect::<String>())
            .collect::<Vec<String>>()
    } else {
        vec![results_as_str; 1]
    };

    let mut i = 0;
    let cluster_name = glob_conf.get_cluster();
    let sensor_name = glob_conf.get_name();

    for message in messages.iter() {
        let msg_chunk = MessageChunk::new(
            sensor_name.clone(),
            cluster_name.clone(),
            message.to_owned(),
        );
        if dev_flag {
            let _ = fs::write(
                format!("./results/chunk_{}.json", i),
                serde_json::to_string(&msg_chunk).unwrap(),
            );
            println!("Wrote to results/chunk_{}.json", i);
        } else {
            kafka_producer
                .as_mut()
                .unwrap()
                .send(&Record::from_value(
                    &format!("monitoring"),
                    serde_json::to_string(&msg_chunk).unwrap(),
                ))
                .unwrap();
            println!("Sent to kafka !");
        }
        i += 1;
    }
    println!("==========");

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), DaemonError> {
    dotenv().ok();
    let redis_connection_url =
        std::env::var("REDIS_CONNECTION_URL").expect("REDIS_CONNECTION_URL must be set.");
    let kafka_connection_url =
        std::env::var("KAFKA_CONNECTION_URL").expect("KAFKA_CONNECTION_URL must be set.");

    let config_path = if env::args().len() == 2 {
        env::args().nth(1).unwrap()
    } else {
        "config.toml".to_owned()
    };

    setting::init_glob_conf(config_path.as_str())?;
    network_stat::init_network_stat_capture()?;

    let monitoring_task = task::spawn(async move {
        let glob_conf = setting::get_glob_conf().unwrap();
        let mut kafka_producer = if !glob_conf.read().unwrap().get_dev_flag() {
            Some(
                Producer::from_hosts(vec![kafka_connection_url])
                    .with_ack_timeout(Duration::from_secs(1))
                    .with_required_acks(RequiredAcks::One)
                    .create()
                    .unwrap(),
            )
        } else {
            None
        };

        let mut interval = time::interval(Duration::from_secs(
            glob_conf.read().unwrap().get_publish_msg_interval(),
        ));
        loop {
            interval.tick().await;
            let _ = read_monitored_data(&mut kafka_producer).await;
        }
    });

    let serve_config_task_change = task::spawn(async move {
        let redis_client = redis::Client::open(redis_connection_url).unwrap();
        let mut connection = redis_client.get_connection().unwrap();
        let mut pubsub = connection.as_pubsub();
        pubsub.subscribe(format!("/update/config/1915940")).unwrap();

        loop {
            let msg = pubsub.get_message().unwrap();
            let payload: String = msg.get_payload().unwrap();
            match update_glob_conf(config_path.clone(), payload) {
                Ok(()) => {
                    println!("Config changes")
                }
                Err(err) => {
                    println!("{}", err)
                }
            };
        }
    });

    match tokio::join!(serve_config_task_change, monitoring_task).0 {
        Ok(_) => Ok(()),
        Err(_) => Err(DaemonError::UnknownErr),
    }
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
