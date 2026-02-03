import express from 'express';
import session, { SessionOptions } from 'express-session';
import { createClient, RedisClientType } from 'redis';
import RedisStore from 'connect-redis';  
import logger from '../utils/logger.js';

/* ──────────────────────────────
   Session type augmentation
────────────────────────────── */
declare module 'express-session' {
  interface SessionData {
    userId?: string;
    userRole?: string;
    authToken?: string;
    mfaVerified?: boolean;
    loginAttempts?: number;
    lastActivity?: number;
    rateLimit?: {
      requests: number[];
      resetTime: number;
    };
    [key: string]: any;
  }
}

/* ──────────────────────────────
   Redis client
────────────────────────────── */
let redisClient: RedisClientType | null = null;

/* ──────────────────────────────
   Initialize Redis session store
────────────────────────────── */
export const initializeSessionStore = async (): Promise<RedisStore | null> => {
  try {
    const redisUrl =
      process.env['REDIS_URL'] ||
      (process.env['NODE_ENV'] === 'development'
        ? 'redis://localhost:6379'
        : null);

    if (!redisUrl) {
      logger.warn('⚠️ Redis URL not set. Falling back to MemoryStore.');
      return null;
    }

    redisClient = createClient({
      url: redisUrl,
      socket: {
        connectTimeout: 10_000,
        reconnectStrategy: (retries) => {
          if (retries > 3) {
            logger.warn('❌ Redis reconnect failed. Giving up.');
            return false;
          }
          return Math.min(retries * 500, 3000);
        },
      },
    });

    redisClient.on('connect', () => logger.info('✅ Redis connected'));
    redisClient.on('reconnecting', () => logger.info('🔄 Redis reconnecting'));
    redisClient.on('error', (err) => logger.error('🔴 Redis error:', err));

    await redisClient.connect();

    // Create RedisStore instance
    const redisStore = new RedisStore({
      client: redisClient,
      prefix: 'session:',
      ttl: 60 * 60 * 24, // 24 hours
    });

    logger.info('✅ Redis session store ready');
    return redisStore;
  } catch (error: any) {
    logger.error('❌ Failed to init Redis session store:', error.message);
    return null;
  }
};

/* ──────────────────────────────
   Session configuration
────────────────────────────── */
export const getSessionConfig = async (): Promise<SessionOptions> => {
  const store = await initializeSessionStore();

  const config: SessionOptions = {
    name: 'FindWork.sid',
    store: store ?? undefined,
    secret: process.env['SESSION_SECRET'] || 'dev-secret-change-me',
    resave: false,
    saveUninitialized: false,
    rolling: true,
    proxy: process.env['NODE_ENV'] === 'production',
    cookie: {
      secure: process.env['NODE_ENV'] === 'production',
      httpOnly: true,
      sameSite: process.env['NODE_ENV'] === 'production' ? 'strict' : 'lax',
      maxAge: 24 * 60 * 60 * 1000,
      domain: process.env['COOKIE_DOMAIN'],
      path: '/',
    },
    genid: () => `sid_${Date.now()}_${Math.random().toString(36).slice(2)}`,
  };

  logger.info('🧩 Session config loaded', {
    store: store ? 'Redis' : 'Memory',
    secure: config.cookie?.secure,
    sameSite: config.cookie?.sameSite,
  });

  return config;
};

/* ──────────────────────────────
   Session middleware factory
────────────────────────────── */
export const createSessionMiddleware =
  async (): Promise<express.RequestHandler> => {
    const config = await getSessionConfig();
    return session(config);
  };

/* ──────────────────────────────
   Helpers
────────────────────────────── */
export const getRedisSessionClient = () => redisClient;

/* ──────────────────────────────
   Health check
────────────────────────────── */
export const checkSessionStoreHealth = async () => {
  try {
    if (redisClient) {
      await redisClient.ping();
      return { healthy: true, store: 'Redis' };
    }
    return { healthy: true, store: 'Memory' };
  } catch (error: any) {
    return {
      healthy: false,
      store: 'Unknown',
      error: error.message,
    };
  }
};

/* ──────────────────────────────
   Default export
────────────────────────────── */
export default createSessionMiddleware;