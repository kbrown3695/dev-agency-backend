import express from 'express';
import session, { SessionOptions } from 'express-session';
import { createClient, RedisClientType } from 'redis';
import connectRedis from 'connect-redis';
import logger from '../utils/logger.js';

// Types for Redis session store
declare module 'express-session' {
  interface SessionData {
    userId?: string;
    userRole?: string;
    authToken?: string;
    mfaVerified?: boolean;
    loginAttempts?: number;
    lastActivity?: number;
    [key: string]: any;
  }
}

// Redis store configuration
let RedisStore: connectRedis.RedisStore;
let redisClient: RedisClientType | null = null;

// Initialize Redis session store
export const initializeSessionStore =
  async (): Promise<connectRedis.RedisStore | null> => {
    try {
      // Get Redis URL from environment
      const redisUrl =
        process.env['REDIS_URL'] ||
        (process.env['NODE_ENV'] === 'development'
          ? 'redis://localhost:6379'
          : null);

      if (!redisUrl) {
        logger.warn('⚠️ Redis URL not configured. Using memory session store.');
        return null;
      }

      // Create Redis client with proper type
      redisClient = createClient({
        url: redisUrl,
        socket: {
          connectTimeout: 10000,
          reconnectStrategy: (retries: number) => {
            if (retries > 3) {
              logger.warn('❌ Too many Redis retries. Using memory store.');
              return false;
            }
            return Math.min(retries * 200, 2000);
          },
        },
      }) as RedisClientType;

      // Setup Redis client events
      redisClient.on('connect', () => {
        logger.info('✅ Redis session store connected');
      });

      redisClient.on('error', (err) => {
        logger.error('🔴 Redis session store error:', err.message);
      });

      redisClient.on('reconnecting', () => {
        logger.info('🔄 Redis session store reconnecting');
      });

      // Connect to Redis
      await redisClient.connect();

      // Create Redis store
      RedisStore = connectRedis(session);

      logger.info('✅ Redis session store initialized');
      return new RedisStore({
        client: redisClient as any, // Type assertion to fix type mismatch
        prefix: 'session:',
        ttl: 86400, // 24 hours in seconds
      });
    } catch (error: any) {
      logger.error(
        '❌ Failed to initialize Redis session store:',
        error.message,
      );
      return null;
    }
  };

// Session configuration
export const getSessionConfig = async (): Promise<SessionOptions> => {
  const store = await initializeSessionStore();

  const sessionConfig: SessionOptions = {
    store: store || undefined, // Use memory store if Redis fails
    secret: process.env['SESSION_SECRET'] || 'dev-secret-change-in-production',
    name: 'FindWork.sid',
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
      secure: process.env['NODE_ENV'] === 'production',
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
      sameSite: process.env['NODE_ENV'] === 'production' ? 'strict' : 'lax',
      domain: process.env['COOKIE_DOMAIN'],
      path: '/',
    },
    proxy: process.env['NODE_ENV'] === 'production', // Trust reverse proxy in production
    genid: () => {
      // Generate custom session ID
      return `sid_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    },
  };

  // Log session configuration (without sensitive data)
  logger.info('Session configuration:', {
    storeType: store ? 'Redis' : 'Memory',
    secureCookie: sessionConfig.cookie?.secure,
    sameSite: sessionConfig.cookie?.sameSite,
    environment: process.env['NODE_ENV'],
  });

  return sessionConfig;
};

// Session middleware - FIXED WITH EXPLICIT RETURN TYPE
export const createSessionMiddleware =
  async (): Promise<express.RequestHandler> => {
    const sessionConfig = await getSessionConfig();
    return session(sessionConfig);
  };

// Session management utilities
export class SessionManager {
  /**
   * Create session for authenticated user
   */
  static createUserSession(req: any, userId: string, userData: any = {}): void {
    req.session.userId = userId;
    req.session.userRole = userData.role;
    req.session.authToken = userData.token;
    req.session.mfaVerified = userData.mfaVerified || false;
    req.session.lastActivity = Date.now();

    // Add additional user data if needed
    Object.assign(req.session, userData.sessionData || {});

    logger.info(`✅ Session created for user: ${userId}`);
  }

  /**
   * Destroy user session
   */
  static destroyUserSession(req: any, res: any): Promise<void> {
    return new Promise((resolve, reject) => {
      const userId = req.session?.userId;

      req.session.destroy((err: any) => {
        if (err) {
          logger.error('Error destroying session:', err);
          reject(err);
        } else {
          // Clear session cookie
          res.clearCookie('FindWork.sid', {
            httpOnly: true,
            secure: process.env['NODE_ENV'] === 'production',
            sameSite: 'strict',
          });

          logger.info(`✅ Session destroyed for user: ${userId}`);
          resolve();
        }
      });
    });
  }

  /**
   * Update session last activity
   */
  static updateLastActivity(req: any): void {
    if (req.session) {
      req.session.lastActivity = Date.now();
    }
  }

  /**
   * Check if session is active
   */
  static isSessionActive(req: any): boolean {
    if (!req.session?.lastActivity) return false;

    const sessionMaxAge = 24 * 60 * 60 * 1000; // 24 hours
    const timeSinceLastActivity = Date.now() - req.session.lastActivity;

    return timeSinceLastActivity < sessionMaxAge;
  }

  /**
   * Get session information
   */
  static getSessionInfo(req: any): {
    userId?: string;
    userRole?: string;
    active: boolean;
    age: number;
  } {
    const lastActivity = req.session?.lastActivity || 0;
    const age = lastActivity ? Date.now() - lastActivity : 0;

    return {
      userId: req.session?.userId,
      userRole: req.session?.userRole,
      active: this.isSessionActive(req),
      age: Math.floor(age / 1000), // Convert to seconds
    };
  }

  /**
   * Clean up expired sessions
   */
  static async cleanupExpiredSessions(): Promise<void> {
    try {
      if (redisClient) {
        // Redis automatically expires sessions based on TTL
        logger.info('✅ Session cleanup completed (Redis TTL)');
      } else {
        logger.info('✅ Memory session store - no cleanup needed');
      }
    } catch (error: any) {
      logger.error('Session cleanup error:', error.message);
    }
  }

  /**
   * Get all active sessions (Admin only)
   */
  static async getAllSessions(pattern: string = 'session:*'): Promise<any[]> {
    try {
      if (!redisClient) {
        logger.warn('Cannot get sessions: Redis not connected');
        return [];
      }

      const keys = await redisClient.keys(pattern);
      const sessions = [];

      for (const key of keys) {
        try {
          const sessionData = await redisClient.get(key);
          if (sessionData) {
            const parsedData = JSON.parse(sessionData);
            sessions.push({
              key,
              userId: parsedData.userId,
              role: parsedData.userRole,
              lastActivity: parsedData.lastActivity,
              cookie: parsedData.cookie,
            });
          }
        } catch (error) {
          logger.warn(`Failed to parse session data for key: ${key}`);
        }
      }

      return sessions;
    } catch (error: any) {
      logger.error('Error getting sessions:', error.message);
      return [];
    }
  }

  /**
   * Destroy session by ID (Admin only)
   */
  static async destroySessionById(sessionId: string): Promise<boolean> {
    try {
      if (!redisClient) {
        logger.warn('Cannot destroy session: Redis not connected');
        return false;
      }

      const key = `session:${sessionId}`;
      const result = await redisClient.del(key);

      if (result > 0) {
        logger.info(`✅ Session destroyed by ID: ${sessionId}`);
        return true;
      }

      return false;
    } catch (error: any) {
      logger.error('Error destroying session by ID:', error.message);
      return false;
    }
  }
}

// Rate limiting using sessions
export const sessionRateLimit = {
  windowMs: 15 * 60 * 1000, // 15 minutes
  maxRequests: 100,

  checkRateLimit(req: any): { allowed: boolean; remaining: number } {
    if (!req.session) {
      return { allowed: true, remaining: this.maxRequests };
    }

    const now = Date.now();
    const windowStart = now - this.windowMs;

    // Initialize rate limit data
    if (!req.session.rateLimit) {
      req.session.rateLimit = {
        requests: [],
        resetTime: now + this.windowMs,
      };
    }

    // Remove old requests
    req.session.rateLimit.requests = req.session.rateLimit.requests.filter(
      (timestamp: number) => timestamp > windowStart,
    );

    // Check if limit exceeded
    if (req.session.rateLimit.requests.length >= this.maxRequests) {
      return {
        allowed: false,
        remaining: 0,
      };
    }

    // Add current request
    req.session.rateLimit.requests.push(now);
    req.session.rateLimit.resetTime = now + this.windowMs;

    return {
      allowed: true,
      remaining: this.maxRequests - req.session.rateLimit.requests.length,
    };
  },
};

// Session timeout middleware
export const sessionTimeoutMiddleware = (
  timeoutMs: number = 24 * 60 * 60 * 1000,
) => {
  return (req: any, res: any, next: any) => {
    if (req.session) {
      const lastActivity = req.session.lastActivity || 0;
      const timeSinceLastActivity = Date.now() - lastActivity;

      if (timeSinceLastActivity > timeoutMs) {
        // Session expired
        SessionManager.destroyUserSession(req, res)
          .then(() => {
            res.status(401).json({
              success: false,
              error: 'Session expired. Please login again.',
            });
          })
          .catch(() => next());
      } else {
        // Update last activity
        req.session.lastActivity = Date.now();
        next();
      }
    } else {
      next();
    }
  };
};

// Session validation middleware
export const validateSessionMiddleware = (
  options: {
    requireAuth?: boolean;
    requiredRoles?: string[];
    requireMfa?: boolean;
  } = {},
) => {
  const {
    requireAuth = true,
    requiredRoles = [],
    requireMfa = false,
  } = options;

  return (req: any, res: any, next: any) => {
    // Check if session exists
    if (!req.session) {
      return res.status(401).json({
        success: false,
        error: 'No session found',
      });
    }

    // Check if authenticated
    if (requireAuth && !req.session.userId) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required',
      });
    }

    // Check MFA verification
    if (requireMfa && !req.session.mfaVerified) {
      return res.status(403).json({
        success: false,
        error: 'MFA verification required',
      });
    }

    // Check user role
    if (requiredRoles.length > 0) {
      const userRole = req.session.userRole;

      if (!userRole || !requiredRoles.includes(userRole)) {
        return res.status(403).json({
          success: false,
          error: 'Insufficient permissions',
        });
      }
    }

    // Session is valid
    next();
  };
};

// Export default session middleware
export default createSessionMiddleware;

// Export helper functions
export const getRedisSessionClient = () => redisClient;

// Health check for session store
export const checkSessionStoreHealth = async () => {
  try {
    if (redisClient) {
      await redisClient.ping();
      return {
        healthy: true,
        store: 'Redis',
        connected: true,
      };
    }

    return {
      healthy: true,
      store: 'Memory',
      connected: true,
    };
  } catch (error: any) {
    return {
      healthy: false,
      store: 'Unknown',
      connected: false,
      error: error.message,
    };
  }
};
