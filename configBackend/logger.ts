import { transports, format, createLogger } from "winston";
import "winston-daily-rotate-file";
const { combine, timestamp, label, printf } = format;

const LOG_DIR = '/data/log/virtual-sensor-config'


const logFormat = printf(({ level, message, label, timestamp }) => {
    return `${timestamp} [${level}]: ${message}`;
  });

var errorTransport = new transports.DailyRotateFile({
  filename: LOG_DIR + '/virtual-sensor-config-%DATE%_error.log',
  datePattern: 'YYYY-MM-DD-HH',
  zippedArchive: true,
  maxSize: '20m',
  maxFiles: '14d',
  level: 'error'
});

var combinedTransport = new transports.DailyRotateFile({
    filename: LOG_DIR + '/virtual-sensor-config-%DATE%.log',
    datePattern: 'YYYY-MM-DD-HH',
    zippedArchive: true,
    maxSize: '20m',
    maxFiles: '14d',
  });


const logger = createLogger({
  level: 'debug',
  format: combine(
    format.colorize(),
    label({ label: 'right meow!' }),
    format.timestamp({
        format: 'MMM-DD-YYYY HH:mm:ss'
    }),
    logFormat
  ),
  defaultMeta: { service: 'user-service' },
  transports: [
    new transports.Console(),
    errorTransport,
    combinedTransport
  ],
});

export default logger;