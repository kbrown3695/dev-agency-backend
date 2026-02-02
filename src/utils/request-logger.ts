// src/utils/request-logger.ts
import { Request, Response, NextFunction } from 'express';
import { AppLogger } from './logger.js';

export const requestLogger = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    const start = Date.now();
    const { method, originalUrl, ip, user } = req;

    // Log request start
    AppLogger.http(`Started ${method} ${originalUrl}`, {
      ip,
      userId: (user as any)?.id,
      userAgent: req.get('user-agent'),
    });

    // Capture response
    res.on('finish', () => {
      const duration = Date.now() - start;
      const { statusCode } = res;

      AppLogger.apiRequest(
        method,
        originalUrl,
        statusCode,
        duration,
        (user as any)?.id,
        {
          ip,
          userAgent: req.get('user-agent'),
          contentLength: res.get('content-length'),
          referrer: req.get('referrer'),
        },
      );
    });

    next();
  };
};

export const errorLogger = (
  error: Error,
  req: Request,
//   res: Response,
  next: NextFunction,
) => {
  AppLogger.error(`Unhandled error: ${error.message}`, error, {
    url: req.originalUrl,
    method: req.method,
    userId: (req.user as any)?.id,
    ip: req.ip,
  });

  next(error);
};
