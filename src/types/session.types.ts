export interface SessionUser {
  userId: string;
  userRole: string;
  email?: string;
  name?: string;
  avatar?: string;
  permissions?: string[];
}

export interface SessionData {
  userId?: string;
  userRole?: string;
  authToken?: string;
  mfaVerified?: boolean;
  loginAttempts?: number;
  lastActivity?: number;
  ipAddress?: string;
  userAgent?: string;
  rateLimit?: {
    requests: number[];
    resetTime: number;
  };
  [key: string]: any;
}

export interface SessionConfig {
  store: 'redis' | 'memory';
  secret: string;
  name: string;
  ttl: number; // in seconds
  cookie: {
    secure: boolean;
    httpOnly: boolean;
    maxAge: number;
    sameSite: 'strict' | 'lax' | 'none';
    domain?: string;
    path: string;
  };
}

export interface SessionInfo {
  sessionId: string;
  userId?: string;
  userRole?: string;
  createdAt: number;
  lastActivity: number;
  expiresAt: number;
  active: boolean;
}

export interface RateLimitInfo {
  allowed: boolean;
  remaining: number;
  resetTime: number;
  limit: number;
  windowMs: number;
}
