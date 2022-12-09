import { Database } from 'sqlite3';
import fs from 'fs';
import logger from '../logger';
import { SensorInfo } from '../type/virtualSensor';

const MODULE_NAME = 'Sensor Repo'


class SensorInfoRepo {
  db: Database | undefined
  setup() {
    this.db = new Database(__dirname + '/db/sensorGateway.sqlite');
    this.db.exec(fs.readFileSync(__dirname + '/sql/sensors.sql').toString());
  }
  getSensorInfo = (sensorId: String): Promise<SensorInfo> => {
    return new Promise<SensorInfo>((resolve, reject) => {
      this.db!.get(
        `SELECT *
        FROM sensors
        WHERE ID = '${sensorId}'`,
        (err, res) => {
          if (err) {
            reject(err);
          } else {
            resolve(res as SensorInfo);
          }
        }
      );
    });
  }
}

export const infoRepo = new SensorInfoRepo();
