// Remove unused import
// import { ObjectId } from 'mongodb';

import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import prisma from '../config/db.js';

// ==================== TYPES ====================

/**
 * User object we attach after authentication
 */
export interface AuthUser {
  id: string;
  email: string;
  role: string;
  firstName: string | null;
  lastName: string | null;
  displayName: string | null;
  avatarUrl: string | null;
  location: string | null;
  phone: string | null;
  emailVerified: boolean;
  isActive: boolean;
  lastLogin: Date | null;
  [key: string]: any;
}

/**
 * Override Passport's User type and extend Express Request
 * This fixes the conflict with @types/passport which already defines Express.User
 */
declare global {
  namespace Express {
    // Override Passport's User interface
    interface User extends AuthUser {}

    interface Request {
      token?: string;
    }
  }
}

// ==================== CONFIGURATION ====================

const JWT_SECRET = process.env['JWT_SECRET'] as string;
const JWT_EXPIRES_IN = process.env['JWT_EXPIRES_IN'] || '7d';
const NODE_ENV = process.env['NODE_ENV'] || 'development';

// Validate JWT secret
if (!JWT_SECRET || JWT_SECRET === 'secret') {
  console.error('FATAL: JWT_SECRET is not defined or is using default value');
  if (NODE_ENV === 'production') {
    process.exit(1);
  }
}

// ==================== TOKEN MANAGEMENT ====================

/**
 * Generate JWT token
 */
export const generateToken = (user: any) => {
  const payload = {
    id: user.id,
    email: user.email,
    role: user.role,
    firstName: user.firstName || '',
    lastName: user.lastName || null,
    displayName: user.displayName || null,
    emailVerified: user.emailVerified || false,
    isActive: user.isActive !== false,
    iat: Math.floor(Date.now() / 1000),
  };

  console.log('🔐 Generating token for user:', {
    id: payload.id,
    email: payload.email,
    role: payload.role,
  });

  const token = jwt.sign(payload, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN as any,
    issuer: 'dev-agency-backend',
    subject: user.id,
    audience: 'dev-agency-app',
  });

  return { token };
};

/**
 * Verify JWT token
 */
export const verifyToken = (token: string) => {
  try {
    return jwt.verify(token, JWT_SECRET, {
      issuer: 'dev-agency-backend',
      audience: 'dev-agency-app',
    });
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      throw new Error('Token expired');
    } else if (error instanceof jwt.JsonWebTokenError) {
      throw new Error('Invalid token');
    } else {
      throw new Error('Token verification failed');
    }
  }
};

/**
 * Extract token from request
 */
export const extractToken = (req: Request): string | null => {
  // Check Authorization header (primary method)
  const authHeader = req.headers['authorization'];
  if (authHeader) {
    const [bearer, token] = authHeader.split(' ');
    if (bearer === 'Bearer' && token) {
      console.log('🔐 Token extracted from Authorization header');
      return token;
    }
  }

  // Check cookies (for web clients)
  if (req.cookies) {
    if (req.cookies.auth_token) {
      console.log('🔐 Token extracted from auth_token cookie');
      return req.cookies.auth_token;
    }
    if (req.cookies.accessToken) {
      console.log('🔐 Token extracted from accessToken cookie');
      return req.cookies.accessToken;
    }
  }

  // Check query parameter (for certain use cases)
  const queryToken = req.query['token'];
  if (queryToken && typeof queryToken === 'string') {
    console.log('🔐 Token extracted from query parameter');
    return queryToken;
  }

  console.warn('❌ No token found in request');
  return null;
};

// ==================== AUTHENTICATION MIDDLEWARE ====================

/**
 * Optional authentication middleware
 * - Attaches user if token is valid
 * - Allows request to continue even if unauthenticated
 */
export const optionalAuth = async (
  req: Request,
  _res: Response,
  next: NextFunction,
): Promise<void> => {
  try {
    const token = extractToken(req);

    if (!token) {
      return next();
    }

    const decoded = verifyToken(token) as {
      id?: string;
      email?: string;
      role?: string;
      [key: string]: any;
    };

    if (!decoded.id) {
      return next();
    }

    const user = await prisma.user.findUnique({
      where: { id: decoded.id },
      select: {
        id: true,
        email: true,
        role: true,
        isActive: true,
        firstName: true,
        lastName: true,
        displayName: true,
        emailVerified: true,
        avatarUrl: true,
        phone: true,
        location: true,
        lastLogin: true,
      },
    });

    if (!user || !user.isActive) {
      return next();
    }

    // Attach user to request
    req.user = {
      id: user.id,
      email: user.email,
      role: user.role,
      firstName: user.firstName || '',
      lastName: user.lastName,
      displayName: user.displayName,
      avatarUrl: user.avatarUrl,
      location: user.location,
      phone: user.phone,
      emailVerified: user.emailVerified,
      isActive: user.isActive,
      lastLogin: user.lastLogin,
    };
    req.token = token;

    console.log('✅ Optional auth - User authenticated:', {
      id: user.id,
      email: user.email,
      role: user.role,
    });

    next();
  } catch (error: any) {
    console.log('Optional auth failed, continuing:', error.message);
    next();
  }
};

/**
 * Required authentication middleware
 * - Stops request if user is not authenticated
 */
export const requireAuth = async (
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> => {
  try {
    const token = extractToken(req);

    if (!token) {
      console.log('❌ No token provided');
      res.status(401).json({
        success: false,
        error: 'Access denied. No token provided.',
      });
      return;
    }

    const decoded = verifyToken(token) as {
      id?: string;
      email?: string;
      role?: string;
      [key: string]: any;
    };

    if (!decoded.id) {
      console.log('❌ Invalid token payload');
      res.status(401).json({
        success: false,
        error: 'Invalid token.',
      });
      return;
    }

    const user = await prisma.user.findUnique({
      where: { id: decoded.id },
      select: {
        id: true,
        email: true,
        role: true,
        isActive: true,
        firstName: true,
        lastName: true,
        displayName: true,
        emailVerified: true,
        avatarUrl: true,
        phone: true,
        location: true,
        lastLogin: true,
      },
    });

    if (!user) {
      console.log('❌ User not found for token:', decoded.id);
      res.status(401).json({
        success: false,
        error: 'Invalid token or user not found.',
      });
      return;
    }

    if (!user.isActive) {
      console.log('❌ User account is inactive:', user.id);
      res.status(401).json({
        success: false,
        error: 'Account deactivated.',
      });
      return;
    }

    // Check session validity
    const session = await prisma.session.findFirst({
      where: {
        userId: user.id,
        token: token,
        expiresAt: { gt: new Date() },
        revoked: false,
      },
    });

    if (!session) {
      console.log('❌ No valid session found for user:', user.id);
      res.status(401).json({
        success: false,
        error: 'Session expired or invalid.',
      });
      return;
    }

    // Attach user to request
    req.user = {
      id: user.id,
      email: user.email,
      role: user.role,
      firstName: user.firstName || '',
      lastName: user.lastName,
      displayName: user.displayName,
      avatarUrl: user.avatarUrl,
      location: user.location,
      phone: user.phone,
      emailVerified: user.emailVerified,
      isActive: user.isActive,
      lastLogin: user.lastLogin,
    };
    req.token = token;

    // Update last activity (non-blocking)
    prisma.session
      .update({
        where: { id: session.id },
        data: { updatedAt: new Date() },
      })
      .catch(console.error);

    console.log('✅ User authenticated:', {
      id: user.id,
      email: user.email,
      role: user.role,
    });

    next();
  } catch (error: any) {
    console.error('❌ Authentication error:', error.message);

    if (error.message === 'Token expired') {
      res.status(401).json({
        success: false,
        error: 'Token expired.',
        message: 'Please refresh your token or login again',
      });
      return;
    }

    if (error.message === 'Invalid token') {
      res.status(401).json({
        success: false,
        error: 'Invalid token.',
      });
      return;
    }

    res.status(500).json({
      success: false,
      error: 'Internal server error during authentication.',
    });
  }
};

// ==================== ROLE-BASED MIDDLEWARE ====================

/**
 * Require admin role middleware
 */
export const requireAdmin = async (
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> => {
  if (!req.user) {
    res.status(401).json({
      success: false,
      error: 'Authentication required',
    });
    return;
  }

  const allowedRoles = ['ADMIN', 'MODERATOR'];
  if (!allowedRoles.includes(req.user.role)) {
    // Log unauthorized access attempt
    await prisma.securityLog.create({
      data: {
        userId: req.user.id,
        action: 'UNAUTHORIZED_ADMIN_ACCESS',
        ipAddress: req.ip || req.connection.remoteAddress || null,
        userAgent: req.get('User-Agent') || null,
        metadata: {
          path: req.path,
          method: req.method,
          userRole: req.user.role,
        },
      },
    });

    res.status(403).json({
      success: false,
      error: 'Access denied. Admin privileges required.',
    });
    return;
  }

  next();
};

/**
 * Require specific roles middleware
 */
export const requireRoles = (...allowedRoles: string[]) => {
  return async (
    req: Request,
    res: Response,
    next: NextFunction,
  ): Promise<void> => {
    if (!req.user) {
      res.status(401).json({
        success: false,
        error: 'Authentication required',
      });
      return;
    }

    if (!allowedRoles.includes(req.user.role)) {
      await prisma.securityLog.create({
        data: {
          userId: req.user.id,
          action: 'UNAUTHORIZED_ROLE_ACCESS',
          ipAddress: req.ip || req.connection.remoteAddress || null,
          userAgent: req.get('User-Agent') || null,
          metadata: {
            path: req.path,
            method: req.method,
            userRole: req.user.role,
            requiredRoles: allowedRoles,
          },
        },
      });

      res.status(403).json({
        success: false,
        error: 'Insufficient permissions',
      });
      return;
    }

    next();
  };
};

// ==================== SPECIALIZED MIDDLEWARE ====================

/**
 * Require vendor role middleware
 */
export const requireVendor = async (
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> => {
  if (!req.user) {
    res.status(401).json({
      success: false,
      error: 'Authentication required',
    });
    return;
  }

  // Fetch user to check vendor status
  const dbUser = await prisma.user.findUnique({
    where: { id: req.user.id },
    select: { isVendor: true },
  });

  if (!dbUser?.isVendor) {
    res.status(403).json({
      success: false,
      error: 'Vendor account required',
      message: 'This feature requires a vendor account',
    });
    return;
  }

  next();
};

/**
 * Require email verification middleware
 */
export const requireEmailVerification = async (
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> => {
  if (!req.user) {
    res.status(401).json({
      success: false,
      error: 'Authentication required',
    });
    return;
  }

  // Fetch user to check email verification status
  const dbUser = await prisma.user.findUnique({
    where: { id: req.user.id },
    select: { emailVerified: true },
  });

  if (!dbUser?.emailVerified) {
    res.status(403).json({
      success: false,
      error: 'Email verification required',
      message: 'Please verify your email address to access this feature',
    });
    return;
  }

  next();
};

// ==================== RATE LIMITING ====================

const rateLimitMap = new Map<string, number[]>();

/**
 * Rate limiting middleware
 */
export const rateLimit = (windowMs = 900000, maxRequests = 100) => {
  // 15 minutes default
  return (req: Request, res: Response, next: NextFunction): void => {
    const key = req.user ? `user:${req.user.id}` : `ip:${req.ip}`;
    const now = Date.now();
    const windowStart = now - windowMs;

    if (!rateLimitMap.has(key)) {
      rateLimitMap.set(key, []);
    }

    const requests = rateLimitMap.get(key)!;
    const recentRequests = requests.filter((time) => time > windowStart);

    if (recentRequests.length >= maxRequests) {
      res.status(429).json({
        success: false,
        error: 'Too many requests',
        message: `Please try again after ${Math.ceil(windowMs / 60000)} minutes`,
        retryAfter: Math.ceil(windowMs / 1000),
      });
      return;
    }

    // Add current request
    recentRequests.push(now);
    rateLimitMap.set(key, recentRequests);

    // Add rate limit headers
    res.set({
      'X-RateLimit-Limit': maxRequests.toString(),
      'X-RateLimit-Remaining': (maxRequests - recentRequests.length).toString(),
      'X-RateLimit-Reset': Math.ceil((now + windowMs) / 1000).toString(),
    });

    next();
  };
};

// Cleanup old rate limit entries periodically
setInterval(
  () => {
    const now = Date.now();
    const twentyFourHoursAgo = now - 24 * 60 * 60 * 1000;

    for (const [key, requests] of rateLimitMap.entries()) {
      const validRequests = requests.filter(
        (time) => time > twentyFourHoursAgo,
      );
      if (validRequests.length === 0) {
        rateLimitMap.delete(key);
      } else {
        rateLimitMap.set(key, validRequests);
      }
    }
  },
  60 * 60 * 1000,
); // Cleanup every hour

// ==================== SESSION MANAGEMENT ====================

/**
 * Clean up expired sessions
 */
export const cleanupExpiredSessions = async (): Promise<void> => {
  try {
    const result = await prisma.session.deleteMany({
      where: {
        expiresAt: { lt: new Date() },
      },
    });

    console.log(`Cleaned up ${result.count} expired sessions`);
  } catch (error) {
    console.error('Error cleaning up expired sessions:', error);
  }
};

// Run session cleanup every hour
setInterval(cleanupExpiredSessions, 60 * 60 * 1000);

// ==================== ALIASES FOR BACKWARD COMPATIBILITY ====================

export const authenticateToken = requireAuth;
export const auth = requireAuth;
export const adminAuth = requireAdmin;
export const requireSuperAdmin = requireRoles.bind(null, 'ADMIN');
export const optionalAuthentication = optionalAuth;
export const checkWhitelistOrSubscription = requireAuth; // Simple alias for now
