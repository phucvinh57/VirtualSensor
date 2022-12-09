import { VirtualSensor } from "./types/virtualSensor.d";

export const parseSensorFromStr = (value: string) => {
  const sensor: VirtualSensor = JSON.parse(value);
  return sensor;
}