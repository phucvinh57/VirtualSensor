import Redis from "ioredis";
import logger from "../logger";
import { infoRepo } from "../repositories/sensorInfoRepo";
import { Sensor } from "../type/virtualSensor";
import { cacheManager } from "./cacheService";

const MODULE_NAME = 'Healthcheck Manager'


class HealthcheckManager {
  redis: Redis | undefined;
  myChannel: string;
  constructor() {
    this.myChannel = 'blank';
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
      this.scribeChannel();
    });
  }

  registerOnMessage(callback: (sensor: Sensor) => void) {
    this.redis!.on('message', async (channel, message) => {
      if (channel !== this.myChannel) return;
    
      const REQUIRE_FIELD = ['name', 'cluster'];
      try {
        const sensor : Sensor = JSON.parse(message);
        logger.debug(`[${MODULE_NAME}] Receive virtual sensor ${JSON.stringify(sensor)}`)
    
        for (const f of REQUIRE_FIELD) {
          if (!(f in sensor)) {
            logger.warn(`[${MODULE_NAME}] No key '${f}' exists`);
            return;
          }
        }

        sensor.lastUpdate = new Date();
        sensor.active = true;
        sensor.info = await infoRepo.getSensorInfo(sensor.id);

        await cacheManager.updateSensor(sensor);

        callback(sensor);

      } catch (err) {
        logger.error(`[${MODULE_NAME}] Error while parse message from redis. Error: ${err}`)
      }
    });
  }

  startDeadDetection(deadTimeout: number, deadDetectCallback: (sensor: Sensor) => void) {
    setInterval(async () => {
      const now = new Date();
      try {
        const sensors: Sensor[] = await cacheManager.getSensors();
        sensors.forEach(async (s) => {
          if (now.getTime() - s.lastUpdate.getTime() > deadTimeout) {
            s.config = await infoRepo.getSensorInfo(s.id);
            logger.debug(`[${MODULE_NAME}] Dead detection. Sensor info: ${JSON.stringify(s)}`);
            s.active = false;
            deadDetectCallback(s);
          }
        });
      } catch (error) {
        logger.error(`[${MODULE_NAME}] Dead detection Error: ${error}`)
      }
    }, deadTimeout);
  }

  private scribeChannel() {
    this.redis!.subscribe(this.myChannel, (err, count) => {
      if (err) {
        logger.error(`[${MODULE_NAME}] Failed to subscribe: %s`, err);
      } else {
        logger.debug(
          `[${MODULE_NAME}] Subscribed successfully! This client is currently subscribed to ${count} channels.`
        );
      }
    });
  }
}

export const healthcheckManager = new HealthcheckManager();