import { SensorConfig, VirtualSensor } from "./types/virtualSensor.d"

export const SENSOR_CONFIG_HINT : {[key in keyof SensorConfig]?: string} = {
  old_kernal: 'Some description',
  capture_size_limit: 'Some description',
  control_command_receive_timeout: 'Some description',
  capture_thread_receive_timeout: 'Some description',
  cpu_to_capture: 'Some description',
  publish_msg_interval: 'Some description',
  dev_flag: 'Some description',
  monitor_targets: 'Some description'
}

export const SENSOR_CONFIG_ALIAS: {[key in keyof SensorConfig]?: string} = {
  old_kernal: 'Old kernel',
  capture_size_limit: 'Capture size limit',
  control_command_receive_timeout: 'Control timeout',
  capture_thread_receive_timeout: 'Thread timeout',
  cpu_to_capture: 'CPU range',
  publish_msg_interval: 'Update interval',
  dev_flag: 'Dev flag',
  monitor_targets: 'Monitor target'
}