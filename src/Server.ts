import express, { Application, Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import dotenv from 'dotenv';
import session from 'express-session';
import passport from 'passport';

// Import configurations
import prisma from './config/db.js';
import { initializeSessionStore } from './config/session.js';
import { initializePassport } from './middlewares/oauth.middleware.js';
import { authenticateToken } from './middlewares/auth.middleware.js';
import logger from './utils/logger.js';

// Import controllers
import { OAuthController } from './controllers/oauth.controller.js';

// Load environment variables
dotenv.config();

// Initialize Express app
const app: Application = express();
const PORT = process.env['PORT'] || 3000;

// ======================
// MIDDLEWARE SETUP
// ======================

app.use(
  helmet({
    crossOriginEmbedderPolicy: false,
  }),
);

// CORS configuration
app.use(
  cors({
    origin: process.env['FRONTEND_URL'],
    credentials: true,
  }),
);

// Body parsing
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Logging
app.use(
  morgan('combined', {
    stream: {
      write: (message: string) => logger.info(message.trim()),
    },
  }),
);

// ======================
// SESSION SETUP
// ======================

const sessionStore = await initializeSessionStore();

app.use(
  session({
    secret: process.env['SESSION_SECRET'] || 'dev-secret',
    resave: false,
    saveUninitialized: false,
    store: sessionStore || undefined,
    cookie: {
      secure: process.env['NODE_ENV'] === 'production',
      httpOnly: true,
      sameSite: process.env['NODE_ENV'] === 'production' ? 'strict' : 'lax',
      maxAge: 24 * 60 * 60 * 1000,
    },
  }),
);

// ======================
// PASSPORT SETUP
// ======================

const passportInstance = initializePassport();
app.use(passportInstance.initialize());
app.use(passportInstance.session());

// ======================
// DATABASE INIT
// ======================

const initializeDatabase = async (): Promise<void> => {
  try {
    await prisma.$connect();
    logger.info('✅ Database connected');

    const users = await prisma.user.count();
    const projects = await prisma.project.count();

    logger.info(`📊 Users: ${users}, Projects: ${projects}`);
  } catch (err) {
    const error = err instanceof Error ? err : new Error(String(err));
    logger.error('❌ Database connection failed', error);
    process.exit(1);
  }
};

// ======================
// ROUTES
// ======================

app.get('/api/health', (_req: Request, res: Response) => {
  res.json({
    status: 'healthy',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
  });
});

app.get('/api/health/db', async (_req: Request, res: Response) => {
  try {
    await prisma.$connect();
    res.json({ success: true });
  } catch (err) {
    const error = err instanceof Error ? err : new Error(String(err));
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});


// OAuth routes
app.post('/api/oauth/google/verify', OAuthController.verifyGoogleToken);
app.get('/api/oauth/config', OAuthController.getOAuthConfig);

app.post(
  '/api/oauth/google/unlink',
  authenticateToken,
  OAuthController.unlinkGoogleAccount,
);

// Passport Google OAuth
app.get(
  '/api/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] }),
);

app.get(
  '/api/auth/google/callback',
  passport.authenticate('google', {
    failureRedirect: '/login',
    session: false,
  }),
  (req: Request, res: Response) => {
    const user = (req as any).user;

    if (!user?.token) {
      return res.redirect(
        `${process.env['FRONTEND_URL']}/login?error=oauth_failed`,
      );
    }

    const redirectUrl = new URL(
      process.env['FRONTEND_URL'] || 'http://localhost:5173',
    );

    redirectUrl.searchParams.set('token', user.token);
    redirectUrl.searchParams.set('email', user.user.email);
    redirectUrl.searchParams.set('oauth', 'true');

    res.redirect(redirectUrl.toString());
  },
);

// Protected route example
app.get('/api/protected', authenticateToken, (req: Request, res: Response) => {
  res.json({
    success: true,
    user: (req as any).user,
  });
});

// ======================
// 404 HANDLER
// ======================

app.use('*', (req: Request, res: Response) => {
  res.status(404).json({
    success: false,
    error: 'Route not found',
    path: req.originalUrl,
  });
});

// ======================
// GLOBAL ERROR HANDLER
// ======================

app.use((error: any, _req: Request, res: Response, _next: NextFunction) => {
  logger.error('Unhandled error', error);

  res.status(error.status || 500).json({
    success: false,
    error: error.message || 'Internal server error',
  });
});

// ======================
// SERVER START
// ======================

const startServer = async (): Promise<void> => {
  await initializeDatabase();

  app.listen(PORT, () => {
    logger.info(`🚀 Server running on port ${PORT}`);
  });
};

startServer();

// ======================
// PROCESS HANDLERS
// ======================

process.on('unhandledRejection', (reason: unknown) => {
     const error = reason instanceof Error ? reason : new Error(String(reason));

  logger.error('Unhandled Rejection', error);
});

process.on('uncaughtException', (error: Error) => {
  logger.error('Uncaught Exception', error);
  process.exit(1);
});

export default app;
 