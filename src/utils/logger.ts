// src/utils/logger.ts
import winston from 'winston';
import path from 'path';
import fs from 'fs';

// Log levels
enum LogLevel {
  ERROR = 'error',
  WARN = 'warn',
  INFO = 'info',
  HTTP = 'http',
  DEBUG = 'debug',
}

// Log colors
const logColors = {
  [LogLevel.ERROR]: 'red',
  [LogLevel.WARN]: 'yellow',
  [LogLevel.INFO]: 'green',
  [LogLevel.HTTP]: 'magenta',
  [LogLevel.DEBUG]: 'blue',
};

// Add colors to winston
winston.addColors(logColors);

// Ensure logs directory exists
const logsDir = path.join(process.cwd(), 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

// Define log format
const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.splat(),
  winston.format.json(),
  winston.format.printf(({ timestamp, level, message, ...meta }) => {
    return `${timestamp} [${level.toUpperCase()}]: ${message} ${
      Object.keys(meta).length ? JSON.stringify(meta, null, 2) : ''
    }`;
  }),
);

// Define console format (pretty print for development)
const consoleFormat = winston.format.combine(
  winston.format.colorize({ all: true }),
  winston.format.timestamp({ format: 'HH:mm:ss' }),
  winston.format.printf(({ timestamp, level, message, ...meta }) => {
    const metaString = Object.keys(meta).length
      ? ` ${JSON.stringify(meta)}`
      : '';
    return `${timestamp} [${level}]: ${message}${metaString}`;
  }),
);

// Create the logger
const logger = winston.createLogger({
  level:
    process.env['NODE_ENV'] === 'development' ? LogLevel.DEBUG : LogLevel.INFO,
  format: logFormat,
  defaultMeta: { service: 'dev-agency-backend' },
  transports: [
    // Console transport (development only)
    new winston.transports.Console({
      format: consoleFormat,
      silent: process.env['NODE_ENV'] === 'production', // Don't log to console in production
    }),

    // Error logs
    new winston.transports.File({
      filename: path.join(logsDir, 'error.log'),
      level: LogLevel.ERROR,
      maxsize: 5242880, // 5MB
      maxFiles: 5,
    }),

    // Combined logs
    new winston.transports.File({
      filename: path.join(logsDir, 'combined.log'),
      maxsize: 5242880, // 5MB
      maxFiles: 5,
    }),

    // HTTP request logs (separate file)
    new winston.transports.File({
      filename: path.join(logsDir, 'http.log'),
      level: LogLevel.HTTP,
      maxsize: 5242880,
      maxFiles: 5,
    }),

    // Debug logs (development only)
    ...(process.env['NODE_ENV'] === 'development'
      ? [
          new winston.transports.File({
            filename: path.join(logsDir, 'debug.log'),
            level: LogLevel.DEBUG,
            maxsize: 10485760, // 10MB
            maxFiles: 3,
          }),
        ]
      : []),
  ],
  exceptionHandlers: [
    new winston.transports.File({
      filename: path.join(logsDir, 'exceptions.log'),
    }),
  ],
  rejectionHandlers: [
    new winston.transports.File({
      filename: path.join(logsDir, 'rejections.log'),
    }),
  ],
});

// Log rotation for production (optional)
if (process.env['NODE_ENV'] === 'production') {
  // You can add log rotation here using winston-daily-rotate-file
}

// Create a stream for Morgan (HTTP logging middleware)
export const morganStream = {
  write: (message: string) => {
    logger.http(message.trim());
  },
};

// Custom logging methods
export class AppLogger {
  // Error logging with context
  static error(message: string, error?: Error, context?: Record<string, any>) {
    const meta = { ...context, stack: error?.stack };
    logger.error(message, meta);
  }

  // Warning logging
  static warn(message: string, context?: Record<string, any>) {
    logger.warn(message, context);
  }

  // Info logging
  static info(message: string, context?: Record<string, any>) {
    logger.info(message, context);
  }

  // HTTP request logging
  static http(message: string, context?: Record<string, any>) {
    logger.http(message, context);
  }

  // Debug logging
  static debug(message: string, context?: Record<string, any>) {
    logger.debug(message, context);
  }

  // Database query logging
  static query(
    model: string,
    operation: string,
    duration: number,
    success: boolean = true,
    context?: Record<string, any>,
  ) {
    const status = success ? '✅' : '❌';
    const message = `${status} [${model}.${operation}] - ${duration}ms`;

    if (success) {
      logger.debug(message, { ...context, type: 'database-query' });
    } else {
      logger.error(message, { ...context, type: 'database-query' });
    }
  }

  // API request logging
  static apiRequest(
    method: string,
    url: string,
    statusCode: number,
    duration: number,
    userId?: string,
    context?: Record<string, any>,
  ) {
    const level = statusCode >= 400 ? LogLevel.WARN : LogLevel.INFO;
    const message = `${method} ${url} - ${statusCode} (${duration}ms)`;

    logger.log(level, message, {
      ...context,
      type: 'api-request',
      method,
      url,
      statusCode,
      duration,
      userId,
    });
  }

  // Authentication logging
  static auth(
    action: string,
    userId?: string,
    success: boolean = true,
    context?: Record<string, any>,
  ) {
    const message = `Auth ${action}: ${success ? 'Success' : 'Failed'}`;

    if (success) {
      logger.info(message, {
        ...context,
        type: 'authentication',
        userId,
        action,
      });
    } else {
      logger.warn(message, {
        ...context,
        type: 'authentication',
        userId,
        action,
      });
    }
  }

  // Business logic logging
  static business(
    action: string,
    entity: string,
    entityId?: string,
    context?: Record<string, any>,
  ) {
    const message = `${action} ${entity}${entityId ? ` #${entityId}` : ''}`;
    logger.info(message, {
      ...context,
      type: 'business-logic',
      entity,
      entityId,
      action,
    });
  }

  // Get logger instance
  static getLogger() {
    return logger;
  }

  // Get logs directory
  static getLogsDir() {
    return logsDir;
  }

  // Clean old logs (optional utility)
  static cleanupOldLogs(daysToKeep: number = 30) {
    const files = fs.readdirSync(logsDir);
    const cutoff = Date.now() - daysToKeep * 24 * 60 * 60 * 1000;

    files.forEach((file) => {
      const filePath = path.join(logsDir, file);
      const stats = fs.statSync(filePath);

      if (stats.mtimeMs < cutoff) {
        fs.unlinkSync(filePath);
        logger.info(`Deleted old log file: ${file}`);
      }
    });
  }
}

// Export the default logger instance
export default AppLogger;
