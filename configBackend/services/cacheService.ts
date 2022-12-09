import Redis from "ioredis";
import logger from "../logger";
import { Sensor } from "../type/virtualSensor";
import { infoRepo } from "../repositories/sensorInfoRepo";


const MODULE_NAME = 'Cache Manager';

class CacheManager {
  redis: Redis | undefined;
  myChannel: string;
  constructor() {
    this.myChannel = 'Blank';
  }
  setup(channel: string) {
    this.myChannel = channel;
    this.redis = new Redis({
      reconnectOnError(err) {
        logger.warn(`[${MODULE_NAME}] Reconnect redis. Error: ${err}`);
        return true;
      },
    });
    this.redis!.on('connect', () => {
      logger.debug(`[${MODULE_NAME}] Connect to config redis successfully`)
    });
  }

  async getSensors (): Promise<Sensor[]> {
    const trackingSensors : Record<string,string> = await this.redis!.hgetall(this.myChannel);
    return (Object.keys(trackingSensors) as Array<string>).map(key => {
      const sensor : Sensor = JSON.parse(trackingSensors[key]);
      sensor.lastUpdate = new Date(sensor.lastUpdate);
      return sensor;
    });
  }

  async updateSensor(sensor: Sensor) {

    if (!sensor.config) {
      const str = await this.redis!.hget(this.myChannel, sensor.id);
      if (str) {
        sensor.config = JSON.parse(str).config;
      }
    }
    
    logger.debug(JSON.stringify(sensor));

    await this.redis!.hset(this.myChannel, {
      [sensor.id]: JSON.stringify(sensor)
    });
  }
}

export const cacheManager = new CacheManager();