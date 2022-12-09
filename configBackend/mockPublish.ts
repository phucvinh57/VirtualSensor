import logger from './logger';
import Redis from 'ioredis';

const SENSOR_CHANNEL = 'virtual-sensor-config';

const pubRedis = new Redis({
  reconnectOnError(err) {
    logger.warn(`Reconnect subcriber redis. Error: ${err}`);
    return true;
  },
});

setInterval(() => {
  const ids = ['H60001', 'H60002'];
  for (let i = 0; i < 2; i++) {
    const data = JSON.stringify(  {
      id: ids[i],
      name: `${i}`,
      cluster: 'H6',
      // config: {
      //   "old_kernel": false,
      //   "capture_size_limit": 4096,
      //   "control_command_receive_timeout": 1000000,
      //   "capture_thread_receive_timeout": 500000,
      //   "cpu_to_capture": "1-1024",
      //   "publish_msg_interval": 10,
      //   "dev_flag": true,
      //   "monitor_targets": [
      //     {
      //       "container_name": "/",
      //       "pid_list": [
      //         264
      //       ]
      //     }
      //   ],
      //   "filter": {
      //     "unix_timestamp": false,
      //     "network_rawstat": {
      //       "interface_rawstat": {
      //         "iname": true,
      //         "description": true,
      //         "uni_connection_stats": true
      //       }
      //     },
      //     "process": {
      //       "pid": true,
      //       "parent_pid": true,
      //       "uid": false,
      //       "effective_uid": false,
      //       "saved_uid": false,
      //       "fs_uid": false,
      //       "gid": false,
      //       "effective_gid": false,
      //       "saved_gid": false,
      //       "fs_gid": false,
      //       "real_pid": false,
      //       "real_parent_pid": false,
      //       "real_uid": false,
      //       "real_effective_uid": false,
      //       "real_saved_uid": false,
      //       "real_fs_uid": false,
      //       "real_gid": false,
      //       "real_effective_gid": false,
      //       "real_saved_gid": false,
      //       "real_fs_gid": false,
      //       "exec_path": true,
      //       "command": true,
      //       "child_real_pid_list": true,
      //       "stat": {
      //         "timestamp": true,
      //         "total_system_cpu_time": true,
      //         "total_user_cpu_time": true,
      //         "total_cpu_time": true,
      //         "total_rss": true,
      //         "total_vss": true,
      //         "total_swap": true,
      //         "total_io_read": true,
      //         "total_io_write": true,
      //         "total_block_io_read": true,
      //         "total_block_io_write": true,
      //         "netstat": {
      //           "pack_sent": true,
      //           "pack_recv": true,
      //           "total_data_sent": true,
      //           "total_data_recv": true,
      //           "real_data_sent": true,
      //           "real_data_recv": true,
      //           "interface_stat": {
      //             "iname": true,
      //             "packet_sent": true,
      //             "packet_recv": true,
      //             "total_data_sent": true,
      //             "total_data_recv": true,
      //             "real_data_sent": true,
      //             "real_data_recv": true,
      //             "connection_stats": true
      //           }
      //         }
      //       },
      //       "thread": {
      //         "tid": true,
      //         "pid": true,
      //         "real_tid": true,
      //         "real_pid": true,
      //         "stat": {
      //           "timestamp": true,
      //           "total_system_cpu_time": true,
      //           "total_user_cpu_time": true,
      //           "total_cpu_time": true,
      //           "total_io_read": true,
      //           "total_io_write": true,
      //           "total_block_io_read": true,
      //           "total_block_io_write": true
      //         }
      //       }
      //     }
      //   }
      // }
    });
    pubRedis.publish(SENSOR_CHANNEL, data);
  }
}, 1000);