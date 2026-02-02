import redisClient from '../config/redis.js';
import logger from './logger.js';

export class CacheUtil {
  /**
   * Get cached data with automatic refresh
   */
  static async getWithRefresh<T>(
    key: string,
    fetchData: () => Promise<T>,
    ttl: number = 3600,
    staleWhileRevalidate: number = 600,
  ): Promise<T> {
    try {
      const cached = await redisClient.get(key);

      if (cached) {
        // Check if data is stale
        const cacheInfo = await redisClient.get(`${key}:info`);
        const age = cacheInfo?.timestamp ? Date.now() - cacheInfo.timestamp : 0;

        if (age > ttl * 1000) {
          // Data is stale, refresh in background
          logger.info(`🔄 Refreshing stale cache for: ${key}`);
          fetchData()
            .then((data) => redisClient.cache(key, data, ttl))
            .then(() =>
              redisClient.set(
                `${key}:info`,
                { timestamp: Date.now() },
                { EX: ttl + staleWhileRevalidate },
              ),
            )
            .catch((err) =>
              logger.warn(`⚠️ Background refresh failed: ${err.message}`),
            );
        }

        return cached;
      }
    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error));
      logger.warn(`⚠️ Cache read failed for ${key}:`, err);
    }


    // Fetch fresh data
    const data = await fetchData();

    // Cache with TTL
    await redisClient.cache(key, data, ttl);
    await redisClient.set(
      `${key}:info`,
      { timestamp: Date.now() },
      { EX: ttl + staleWhileRevalidate },
    );

    return data;
  }

  /**
   * Batch get multiple keys
   */
  static async mget<T>(keys: string[]): Promise<(T | null)[]> {
    if (keys.length === 0) return [];

    try {
      const results = await Promise.all(
        keys.map((key) => redisClient.get(key)),
      );
      return results;
    } catch (error) {
        const err = error instanceof Error ? error : new Error(String(error));
        logger.error('Batch get error:', err);
      return new Array(keys.length).fill(null);
    }
  }

  /**
   * Batch set multiple keys
   */
  static async mset(
    items: Array<{ key: string; value: any; ttl?: number }>,
  ): Promise<void> {
    if (items.length === 0) return;

    try {
      await Promise.all(
        items.map(({ key, value, ttl = 3600 }) =>
          redisClient.cache(key, value, ttl),
        ),
      );
      logger.info(`💾 Batch cached ${items.length} items`);
    } catch (error) {
        const err = error instanceof Error ? error : new Error(String(error));
        logger.error('Batch set error:', err);
    }
  }

  /**
   * Cache with tags
   */
  static async tagCache<T>(
    key: string,
    tags: string[],
    fetchData: () => Promise<T>,
    ttl: number = 3600,
  ): Promise<T> {
    const data = await fetchData();

    // Store data
    await redisClient.cache(key, data, ttl);

    // Store tag relationships
    for (const tag of tags) {
      const tagKey = `tag:${tag}`;
      const taggedItems = (await redisClient.get(tagKey)) || [];
      if (!taggedItems.includes(key)) {
        taggedItems.push(key);
        await redisClient.cache(tagKey, taggedItems, ttl);
      }
    }

    return data;
  }

  /**
   * Invalidate cache by tag
   */
  static async invalidateTag(tag: string): Promise<void> {
    const tagKey = `tag:${tag}`;
    try {
      const taggedItems = (await redisClient.get(tagKey)) || [];
      if (taggedItems.length > 0) {
        await redisClient.del(...taggedItems);
        await redisClient.del(tagKey);
        logger.info(
          `🧹 Invalidated ${taggedItems.length} items tagged: ${tag}`,
        );
      }
    } catch (error) {
        const err = error instanceof Error ? error : new Error(String(error));
        logger.error('Error invalidating tag:', err);
    }
  }

  /**
   * Rate limiting using Redis
   */
  static async rateLimit(
    key: string,
    limit: number,
    windowSeconds: number,
  ): Promise<{ allowed: boolean; remaining: number; reset: number }> {
    const now = Math.floor(Date.now() / 1000);
    const windowStart = now - windowSeconds + 1;

    try {
      // Remove old requests
      await (redisClient as any).zremrangebyscore?.(key, 0, windowStart);

      // Count requests in current window
      const requestCount = (await (redisClient as any).zcard?.(key)) || 0;

      if (requestCount >= limit) {
        // Get oldest request to calculate reset time
        const oldest = await (redisClient as any).zrange?.(
          key,
          0,
          0,
          'WITHSCORES',
        );
        const reset = oldest?.[1]
          ? parseInt(oldest[1]) + windowSeconds
          : now + windowSeconds;

        return {
          allowed: false,
          remaining: 0,
          reset,
        };
      }

      // Add current request
      await (redisClient as any).zadd?.(key, now, `${now}-${Math.random()}`);
      await redisClient.expire(key, windowSeconds);

      return {
        allowed: true,
        remaining: limit - requestCount - 1,
        reset: now + windowSeconds,
      };
    } catch (error) {
      // If Redis fails, allow request
      const err = error instanceof Error ? error : new Error(String(error));
      logger.error('Rate limit error:', err);
      return {
        allowed: true,
        remaining: limit,
        reset: now + windowSeconds,
      };
    }
  }
}
