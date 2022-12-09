import { Server } from 'ws';
import logger from './logger';
import Redis from 'ioredis';
import * as dotenv from 'dotenv';
import { Sensor } from './type/virtualSensor.d';

import { healthcheckManager} from './services/healthcheckService';
import { cacheManager } from './services/cacheService';
import { infoRepo } from './repositories/sensorInfoRepo';



dotenv.config();

const MODULE_NAME = 'Main';
const CONFIG_CHANNEL = process.env.CONFIG_CHANNEL ? process.env.CONFIG_CHANNEL : 'virtual-sensor-config';
const HEALTHCHECK_CHANNEL = process.env.HEALTHCHECK_CHANNEL ? process.env.HEALTHCHECK_CHANNEL : 'virtual-sensor-tracking';
const PORT : number = process.env.WEBSOCKET_PORT ? parseInt(process.env.WEBSOCKET_PORT) : 9090;
const DEAD_TIMEOUT : number = process.env.DEAD_TIMEOUT ? parseInt(process.env.DEAD_TIMEOUT) : 2000;

// =================Print server config=================

const configStr = `Sensor channel = ${CONFIG_CHANNEL}` +
  ` | Tracking channel = ${HEALTHCHECK_CHANNEL}` +
  ` | Websocket port = ${PORT}` +
  ` | Dead timeout = ${DEAD_TIMEOUT}`

logger.info(`[Server info] ${configStr}`)

healthcheckManager.setup(CONFIG_CHANNEL);
cacheManager.setup(HEALTHCHECK_CHANNEL);
infoRepo.setup();

healthcheckManager.startDeadDetection(DEAD_TIMEOUT, async (sensor: Sensor) => {
  notifyAllClient(JSON.stringify(sensor));
});

healthcheckManager.registerOnMessage(async (sensor: Sensor) => {
  notifyAllClient(JSON.stringify(sensor));
})


// =================Setup Redis client=================

// const configListener = new Redis({
//   reconnectOnError(err) {
//     logger.warn(`Reconnect redis. Error: ${err}`);
//     return true;
//   },
// });

// const trackRedis = new Redis({
//   reconnectOnError(err) {
//     logger.warn(`[Redis client] Reconnect publisher redis. Error: ${err}`);
//     return true;
//   },
// });

// configListener.subscribe(SENSOR_CHANNEL, (err, count) => {
//   if (err) {
//     logger.error("Failed to subscribe: %s", err.message);
//   } else {
//     logger.debug(
//       `[Redis client] Subscribed successfully! This client is currently subscribed to ${count} channels.`
//     );
//   }
// });

// configListener.on("message", (channel, message) => {
//   if (channel !== SENSOR_CHANNEL) return;

//   const REQUIRE_FIELD = ['name', 'cluster'];
//   try {
//     const sensor : Sensor = JSON.parse(message);
//     logger.debug(`[Redis client] Receive virtual sensor info from server ${JSON.stringify(sensor)}`)

//     for (const f of REQUIRE_FIELD) {
//       if (!(f in sensor)) {
//         throw `No key '${f}' exists`
//       }
//     }
//     sensor.lastUpdate = new Date();

//     trackRedis.hset(TRACKING_CHANNEL, {
//       [sensor.id]: JSON.stringify(sensor)
//     });

//     notifyAllClient(JSON.stringify(sensor));

//   } catch (err) {
//     logger.error(`Error while parse message from redis. Error: ${err}`)
//   }
// });

// setInterval(async () => {
//   const now = new Date();
//   try {
//     const trackingSensors : Record<string,string> = await trackRedis.hgetall(TRACKING_CHANNEL);
//     (Object.keys(trackingSensors) as Array<string>).find(key => {
//       const sensor : Sensor = JSON.parse(trackingSensors[key]);
//       sensor.lastUpdate = new Date(sensor.lastUpdate);
//       if (now.getTime() - sensor.lastUpdate.getTime() > DEAD_TIMEOUT) {
//         logger.debug(`[Dead detection]. Sensor info: ${JSON.stringify(sensor)}`);
//         sensor.active = false;
//         notifyAllClient(JSON.stringify(sensor));
//       }
//     });
//   } catch (error) {
//     logger.error(`[Dead detection] Error: ${error}`)
//   }
// }, DEAD_TIMEOUT)


// =================Setup websocket server=================


const sockserver = new Server({ port: PORT });
sockserver.on('connection', (ws) => {
  logger.debug(`[${MODULE_NAME}] New client connected! Client info: ${ws}`);
  ws.on('close', () => logger.debug(`Client has disconnected! Client info ${ws}`));
  ws.on('open', async () => {
    const sensors : Sensor[] = await cacheManager.getSensors();
    for (const sensor in sensors) {
      ws.send(JSON.stringify(sensor), (error) => {
        if (error) {
          logger.error(`[Websocket client] On open callback error. Error: ${error}`);
        }
      });
    }
  });
});

function notifyAllClient(message: string) {
  sockserver.clients.forEach((client) => {
    client.send(message, (error) => {
      if (error) {
        logger.error(`[Websocket client] Notify all client error. Error: ${error}`);
      }
    });
  });
}