export declare type Sensor = {
  id: string,
  info: SensorInfo,
  active: boolean,
  lastUpdate: Date,
  config: any,
};

export declare type SensorInfo = {
  name: string;
  cluster: string;
  description: string,
  config: any,
}