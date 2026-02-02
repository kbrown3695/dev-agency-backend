import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import prisma from '../config/db.js';

/**
 * User object we attach after authentication
 */
export interface AuthUser {
  id: string;
  email: string;
  role: string;
  [key: string]: any;
}

/**
 * Local request extension (NO global declaration)
 */
export interface AuthRequest extends Request {
  user?: AuthUser;
}

/**
 * Optional authentication middleware
 * - Attaches user if token is valid
 * - Allows request to continue even if unauthenticated
 */
export const authenticateToken = async (
  req: Request,
  _res: Response,
  next: NextFunction,
): Promise<void> => {
  try {
    const authReq = req as AuthRequest;

    const authHeader = req.headers.authorization;
    const token = authHeader?.split(' ')[1];

    if (!token) {
      return next();
    }

    const jwtSecret = process.env['JWT_SECRET'];
    if (!jwtSecret) {
      return next();
    }

    const decoded = jwt.verify(token, jwtSecret) as {
      id?: string;
      userId?: string;
      sub?: string;
    };

    const userId = decoded.userId || decoded.id || decoded.sub;
    if (!userId) {
      return next();
    }

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        role: true,
        isActive: true,
      },
    });

    if (!user || !user.isActive) {
      return next();
    }

    authReq.user = user;
    next();
  } catch {
    // Invalid token → continue unauthenticated
    next();
  }
};

/**
 * Hard authentication middleware
 * - Stops request if user is not authenticated
 */
export const requireAuth = (
  req: Request,
  res: Response,
  next: NextFunction,
): void => {
  const authReq = req as AuthRequest;

  if (!authReq.user) {
    res.status(401).json({
      success: false,
      error: 'Authentication required',
    });
    return;
  }

  next();
};

/**
 * Role-based authorization middleware
 */
export const requireRole = (...allowedRoles: string[]) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const authReq = req as AuthRequest;

    if (!authReq.user) {
      res.status(401).json({
        success: false,
        error: 'Authentication required',
      });
      return;
    }

    if (!allowedRoles.includes(authReq.user.role)) {
      res.status(403).json({
        success: false,
        error: 'Insufficient permissions',
      });
      return;
    }

    next();
  };
};
