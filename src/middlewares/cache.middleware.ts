import { Request, Response, NextFunction } from 'express';
import redisClient from '../config/redis.js';
import logger from '../utils/logger.js';

export const cacheMiddleware = (ttl: number = 300) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.method !== 'GET') {
      return next();
    }

    const cacheKey = `route:${req.originalUrl || req.url}`;

    try {
      const cached = await redisClient.get(cacheKey);
      if (cached) {
        logger.info(`✅ Route cache hit: ${req.originalUrl}`);
        return res.json(cached);
      }

      const originalJson = res.json.bind(res);

      res.json = (body: any) => {
        redisClient
          .cache(cacheKey, body, ttl)
          .then(() => logger.info(`💾 Route cached: ${req.originalUrl}`))
          .catch((err) =>
            logger.warn(
              `⚠️ Route cache failed: ${err instanceof Error ? err.message : String(err)}`,
            ),
          );

        return originalJson(body);
      };

      next();
    } catch (error) {
      if (error instanceof Error) {
        logger.error('Cache middleware error:', error);
        next(error);
      } else {
        logger.error('Cache middleware error:', new Error(String(error)));
        next();
      }
    }
  };
};

// Clear cache for specific route
export const clearRouteCache = async (pattern: string): Promise<void> => {
  try {
    const keys = await redisClient.keys(`route:${pattern}*`);
    if (keys.length > 0) {
      await redisClient.del(...keys);
      logger.info(`🧹 Cleared cache for pattern: ${pattern}`);
    }
  } catch (error) {
    logger.error(
      'Error clearing route cache:',
      error instanceof Error ? error : new Error(String(error)),
    );
  }
};

// Clear all cache
export const clearAllCache = async (): Promise<void> => {
  try {
    const keys = await redisClient.keys('*');
    if (keys.length > 0) {
      await redisClient.del(...keys);
    }
    logger.info('🧹 Cleared all cache');
  } catch (error) {
    logger.error(
      'Error clearing all cache:',
      error instanceof Error ? error : new Error(String(error)),
    );
  }
};
