import { createClient, RedisClientType, RedisClientOptions } from 'redis';
import logger from '../utils/logger.js';

// Enhanced in-memory cache for development with TTL support
class MemoryCache {
  private store: Map<string, { value: any; expiry: number | null }>;
  private timeouts: Map<string, NodeJS.Timeout>;

  constructor() {
    this.store = new Map();
    this.timeouts = new Map();
    logger.info('💾 Memory cache initialized');
  }

  async get(key: string): Promise<any> {
    const item = this.store.get(key);
    if (!item) return null;

    if (item.expiry && item.expiry < Date.now()) {
      this.store.delete(key);
      this._clearTimeout(key);
      return null;
    }

    return item.value;
  }

  async set(
    key: string,
    value: any,
    expireSeconds: number | null = null,
  ): Promise<string> {
    const item = {
      value,
      expiry: expireSeconds ? Date.now() + expireSeconds * 1000 : null,
    };

    this.store.set(key, item);
    this._clearTimeout(key);

    if (expireSeconds) {
      const timeout = setTimeout(() => {
        this.store.delete(key);
        this.timeouts.delete(key);
      }, expireSeconds * 1000);
      this.timeouts.set(key, timeout);
    }

    return 'OK';
  }

  async del(...keys: string[]): Promise<number> {
    let deleted = 0;
    for (const key of keys) {
      this._clearTimeout(key);
      if (this.store.delete(key)) deleted++;
    }
    return deleted;
  }

  async exists(key: string): Promise<number> {
    return this.store.has(key) ? 1 : 0;
  }

  async expire(key: string, seconds: number): Promise<number> {
    const item = this.store.get(key);
    if (item) {
      this._clearTimeout(key);
      item.expiry = Date.now() + seconds * 1000;

      const timeout = setTimeout(() => {
        this.store.delete(key);
        this.timeouts.delete(key);
      }, seconds * 1000);
      this.timeouts.set(key, timeout);

      return 1;
    }
    return 0;
  }

  async ping(): Promise<string> {
    return 'PONG';
  }

  private _clearTimeout(key: string): void {
    if (this.timeouts.has(key)) {
      clearTimeout(this.timeouts.get(key)!);
      this.timeouts.delete(key);
    }
  }

  async keys(pattern: string = '*'): Promise<string[]> {
    const allKeys = Array.from(this.store.keys());
    const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
    return allKeys.filter((key) => regex.test(key));
  }

  async flushAll(): Promise<string> {
    for (const timeout of this.timeouts.values()) {
      clearTimeout(timeout);
    }
    this.store.clear();
    this.timeouts.clear();
    return 'OK';
  }

  get size(): number {
    return this.store.size;
  }

  async quit(): Promise<void> {
    for (const timeout of this.timeouts.values()) {
      clearTimeout(timeout);
    }
    this.store.clear();
    this.timeouts.clear();
  }
}

const memoryCache = new MemoryCache();

// Define cache options interface
interface CacheOptions {
  EX?: number; // Expire time in seconds
  PX?: number; // Expire time in milliseconds
  EXAT?: number; // Expire timestamp in seconds
  PXAT?: number; // Expire timestamp in milliseconds
  NX?: boolean; // Only set the key if it does not exist
  XX?: boolean; // Only set the key if it already exists
  KEEPTTL?: boolean; // Retain the time to live associated with the key
  GET?: boolean; // Return the old string stored at key, or nil if key did not exist
}

interface RedisStatus {
  isConnected: boolean;
  isUsingFallback: boolean;
  environment: string;
  url: string;
  memoryCacheSize: number | null;
}

class RedisClient {
  private client: RedisClientType | MemoryCache | null = null;
  private isConnected: boolean = false;
  private connectionPromise: Promise<any> | null = null;
  private isUsingFallback: boolean = false;
  private defaultConfig: RedisClientOptions;

  constructor() {
    const url = this._getRedisUrl();

    this.defaultConfig = {
      ...(url ? { url } : {}),
      socket: {
        connectTimeout: 10000,
        reconnectStrategy: (retries: number) => {
          if (retries > 3) {
            logger.warn('❌ Too many Redis retries. Using fallback.');
            return false;
          }
          return Math.min(retries * 200, 2000);
        },
      },
    };
  }

  private _getRedisUrl(): string | undefined {
    if (process.env['REDIS_URL']) {
      return process.env['REDIS_URL'];
    }

    if (process.env['NODE_ENV'] === 'development') {
      return 'redis://localhost:6379';
    }

    logger.warn('⚠️ No Redis configuration found. Using fallback cache.');
    return undefined;
  }

  initialize(config: RedisClientOptions = {}): RedisClient {
    const finalConfig = { ...this.defaultConfig, ...config };

    if (!finalConfig.url) {
      logger.info('🔄 Using fallback cache (no Redis URL available)');
      this.client = memoryCache;
      this.isConnected = true;
      this.isUsingFallback = true;
      return this;
    }

    try {
      this.client = createClient(finalConfig) as RedisClientType;
      this.isUsingFallback = false;
      this._setupEventHandlers();
      logger.info(
        `🔴 Redis client initialized for ${process.env['NODE_ENV'] || 'development'}`,
      );
    } catch (error: any) {
      logger.error('❌ Failed to initialize Redis client:', error.message);
      this.client = memoryCache;
      this.isConnected = true;
      this.isUsingFallback = true;
    }

    return this;
  }

  private _setupEventHandlers(): void {
    if (!this.client || !('on' in this.client)) return;

    const redisClient = this.client as RedisClientType;

    redisClient.on('connect', () => {
      logger.info('✅ Redis client connected');
      this.isConnected = true;
      this.isUsingFallback = false;
    });

    redisClient.on('ready', () => {
      logger.info('✅ Redis client ready');
      this.isConnected = true;
      this.isUsingFallback = false;
    });

    redisClient.on('error', (err) => {
      logger.error('🔴 Redis client error:', err.message);
      this.isConnected = false;
    });

    redisClient.on('end', () => {
      logger.info('🔌 Redis client disconnected');
      this.isConnected = false;
    });

    redisClient.on('reconnecting', () => {
      logger.info('🔄 Redis client reconnecting');
      this.isConnected = false;
    });
  }

  async connect(): Promise<RedisClientType | MemoryCache> {
    if (this.isUsingFallback) {
      return this.client!;
    }

    if (this.connectionPromise) {
      return this.connectionPromise;
    }

    if (!this.client) {
      this.initialize();
    }

    if (this.isUsingFallback) {
      this.isConnected = true;
      return this.client!;
    }

    this.connectionPromise = (async () => {
      try {
        if (!(this.client as RedisClientType).isOpen) {
          await (this.client as RedisClientType).connect();
          await (this.client as RedisClientType).ping();
        }
        logger.info('✅ Redis connection established and verified');
        this.isUsingFallback = false;
        return this.client!;
      } catch (error: any) {
        logger.error('❌ Failed to connect to Redis:', error.message);
        this.client = memoryCache;
        this.isConnected = true;
        this.isUsingFallback = true;
        this.connectionPromise = null;
        return this.client!;
      }
    })();

    return this.connectionPromise;
  }

  async get(key: string, parseJSON: boolean = true): Promise<any> {
    await this._ensureConnection();
    try {
      const value = await (this.client as any).get(key);
      if (!value) return null;

      if (parseJSON) {
        try {
          return JSON.parse(value);
        } catch (error: any) {
          logger.warn(
            `⚠️ Failed to parse JSON for key "${key}":`,
            error.message,
          );
          return value;
        }
      }
      return value;
    } catch (error: any) {
      logger.error('Redis get error:', error.message);
      return null;
    }
  }

  async set(
    key: string,
    value: any,
    options: CacheOptions | number = {},
  ): Promise<string | null> {
    await this._ensureConnection();
    try {
      let valueToStore: string;
      if (typeof value === 'string') {
        valueToStore = value;
      } else if (typeof value === 'object' && value !== null) {
        try {
          valueToStore = JSON.stringify(value);
        } catch (error: any) {
          logger.error(
            `Failed to stringify value for key "${key}":`,
            error.message,
          );
          return null;
        }
      } else {
        valueToStore = String(value);
      }

      const setOptions =
        typeof options === 'number' ? { EX: options } : options;
      return await (this.client as any).set(key, valueToStore, setOptions);
    } catch (error: any) {
      logger.error('Redis set error:', error.message);
      return null;
    }
  }

  async cache(
    key: string,
    data: any,
    ttl: number = 3600,
  ): Promise<string | null> {
    return this.set(key, data, { EX: ttl });
  }

  async del(...keys: string[]): Promise<number> {
    await this._ensureConnection();
    try {
      if (keys.length === 0) return 0;
      return await (this.client as any).del(...keys);
    } catch (error: any) {
      logger.error('Redis del error:', error.message);
      return 0;
    }
  }

  async exists(key: string): Promise<number> {
    await this._ensureConnection();
    try {
      return await (this.client as any).exists(key);
    } catch (error: any) {
      logger.error('Redis exists error:', error.message);
      return 0;
    }
  }

  async expire(key: string, ttl: number): Promise<number> {
    await this._ensureConnection();
    try {
      return await (this.client as any).expire(key, ttl);
    } catch (error: any) {
      logger.error('Redis expire error:', error.message);
      return 0;
    }
  }

  async keys(pattern: string): Promise<string[]> {
    await this._ensureConnection();
    try {
      return await (this.client as any).keys(pattern);
    } catch (error: any) {
      logger.error('Redis keys error:', error.message);
      return [];
    }
  }

  private async _ensureConnection(): Promise<void> {
    if (!this.isConnected) {
      await this.connect();
    }
  }

  async ping(): Promise<boolean> {
    try {
      await this._ensureConnection();
      const result = await (this.client as any).ping();
      return result === 'PONG';
    } catch (error: any) {
      logger.error('Redis ping failed:', error.message);
      this.isConnected = false;
      return false;
    }
  }

  async disconnect(): Promise<void> {
    if (
      this.client &&
      'disconnect' in this.client &&
      this.isConnected &&
      !this.isUsingFallback
    ) {
      try {
        await (this.client as RedisClientType).disconnect();
        logger.info('✅ Redis disconnected gracefully');
      } catch (error: any) {
        logger.error('Error disconnecting Redis:', error.message);
      }
    }
    this.isConnected = false;
    this.connectionPromise = null;
  }

  async quit(): Promise<void> {
    if (this.client && 'quit' in this.client && !this.isUsingFallback) {
      try {
        await (this.client as RedisClientType).quit();
      } catch (error: any) {
        // Ignore quit errors
      }
    } else if (this.client && 'quit' in this.client) {
      await (this.client as MemoryCache).quit();
    }
    this.isConnected = false;
    this.connectionPromise = null;
  }

  getStatus(): RedisStatus {
    return {
      isConnected: this.isConnected,
      isUsingFallback: this.isUsingFallback,
      environment: process.env['NODE_ENV'] || 'development',
      url:
        this._getRedisUrl()?.replace(/:[^:]*@/, ':****@') || 'fallback-cache',
      memoryCacheSize: this.isUsingFallback ? memoryCache.size : null,
    };
  }

  isRedisAvailable(): boolean {
    return !this.isUsingFallback && this.isConnected;
  }
}

const redisClient = new RedisClient();
redisClient.initialize();

// Helper functions
export const connectRedis = async (): Promise<RedisClient> => {
  await redisClient.connect();
  return redisClient;
};

export const getRedisStatus = (): RedisStatus => redisClient.getStatus();

export const cacheWithFallback = async <T>(
  key: string,
  fetchData: () => Promise<T>,
  ttl: number = 3600,
): Promise<T> => {
  try {
    const cached = await redisClient.get(key);
    if (cached) {
      logger.info(`✅ Cache hit: ${key}`);
      return cached as T;
    }
  } catch (error: any) {
    logger.info(`❌ Cache miss, fetching fresh data for key: ${key}`);
  }

  const data = await fetchData();

  redisClient
    .cache(key, data, ttl)
    .then(() => logger.info(`💾 Cached: ${key}`))
    .catch((err: any) => logger.warn(`⚠️ Cache set failed: ${err.message}`));

  return data;
};

// Cache decorator for methods
export function Cache(ttl: number = 3600, keyPrefix: string = '') {
  return function (
    target: any,
    propertyKey: string,
    descriptor: PropertyDescriptor,
  ) {
    const originalMethod = descriptor.value;

    descriptor.value = async function (...args: any[]) {
      const cacheKey = `${keyPrefix || target.constructor.name}:${propertyKey}:${JSON.stringify(args)}`;

      try {
        const cached = await redisClient.get(cacheKey);
        if (cached) {
          logger.info(`✅ Cache hit for method: ${propertyKey}`);
          return cached;
        }
      } catch (error) {
        // Continue to execute method if cache fails
      }

      const result = await originalMethod.apply(this, args);

      redisClient
        .cache(cacheKey, result, ttl)
        .catch((err: any) =>
          logger.warn(`⚠️ Method cache set failed: ${err.message}`),
        );

      return result;
    };

    return descriptor;
  };
}

export { RedisClient, redisClient, memoryCache };
export default redisClient;
