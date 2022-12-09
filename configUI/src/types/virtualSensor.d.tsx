// export interface VirtualSensor {
//   name?: string;
//   cluster?: string;
//   active?: boolean,
//   lastUpdate?: string,
//   description?: string,
//   config?: SensorConfig,
// };

export declare type VirtualSensor = {
  id?: string,
  info?: SensorInfo,
  active?: boolean,
  lastUpdate?: string,
  config?: SensorConfig,
};

export declare type SensorInfo = {
  name: string;
  cluster: string;
  description: string,
  config: any,
}

export interface SensorConfig {
  old_kernal: boolean,
  capture_size_limit: number,
  control_command_receive_timeout: number,
  capture_thread_receive_timeout: number,
  cpu_to_capture: string,
  publish_msg_interval: number,
  dev_flag: boolean,
  monitor_targets: MonitorTarget[],
  filter: {
    unix_timestamp: boolean,
    network_rawstat: {
      interface_rawstat: {
        iname: boolean,
        description: boolean,
        uni_connection_stats: boolean
      }
    },
    process: ProcessConfig
  }

}

export interface MonitorTarget {
  container_name: string,
  pid_list: Int32Array
}

export interface ProcessConfig {
  pid: boolean,
  parent_pid: boolean,
  uid: boolean,
  effective_uid: boolean,
  saved_uid: boolean,
  fs_uid: boolean,
  gid: boolean,
  effective_gid: boolean,
  saved_gid: boolean,
  fs_gid: boolean,
  real_pid: boolean,
  real_parent_pid: boolean,
  real_uid: boolean,
  real_effective_uid: boolean,
  real_saved_uid: boolean,
  real_fs_uid: boolean,
  real_gid: boolean,
  real_effective_gid: boolean,
  real_saved_gid: boolean,
  real_fs_gid: boolean,
  exec_path: boolean,
  command: boolean,
  child_real_pid_list: boolean,
  stat: {
    timestamp: boolean,
    total_system_cpu_time: boolean,
    total_user_cpu_time: boolean,
    total_cpu_time: boolean,
    total_rss: boolean,
    total_vss: boolean,
    total_swap: boolean,
    total_io_read: boolean,
    total_io_write: boolean,
    total_block_io_read: boolean,
    total_block_io_write: boolean,
    netstat: {
      pack_sent: boolean,
      pack_recv: boolean,
      total_data_sent: boolean,
      total_data_recv: boolean,
      real_data_sent: boolean,
      real_data_recv: boolean,
      interface_stat: {
        iname: boolean,
        packet_sent: boolean,
        packet_recv: boolean,
        total_data_sent: boolean,
        total_data_recv: boolean,
        real_data_sent: boolean,
        real_data_recv: boolean,
        connection_stats: boolean
      }
    }
  }
}

export const equalSensors = (a:VirtualSensor, b: VirtualSensor) => {
  return a.id === b.id;
}