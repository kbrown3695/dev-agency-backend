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
import logger from './utils/logger.js';
import { emailService } from './services/email.service.js';

// Import routes
import authRoutes from './routes/auth.routes.js';
import oauthRoutes from './routes/oauth.routes.js';

// Load environment variables
dotenv.config();

// Initialize Express app
const app: Application = express();
const PORT = process.env['PORT'] || 5000;

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
    throw error; // Don't exit here, let the startServer handle it
  }
};

// ======================
// EMAIL SERVICE INIT
// ======================

const initializeEmailService = async (): Promise<void> => {
  try {
    const isConnected = await emailService.testConnection();

    if (isConnected) {
      logger.info('✅ Email service connected successfully');

      // Log email service status
      const status = emailService.getStatus();
      logger.info('📧 Email service status:', {
        service: status.service,
        from: status.from,
        isConnected: status.isConnected,
      });
    } else {
      logger.warn(
        '⚠️ Email service connection test failed, emails may not be sent',
      );
    }
  } catch (err) {
    const error = err instanceof Error ? err : new Error(String(err));
    logger.warn('⚠️ Email service initialization warning', {
      message: error.message,
    });
  }
};

// ======================
// SESSION SETUP FUNCTION
// ======================

const setupSessionMiddleware = async () => {
  try {
    const sessionStore = await initializeSessionStore();

    app.use(
      session({
        secret: process.env['SESSION_SECRET'] || 'dev-secret',
        resave: false,
        saveUninitialized: false,
        store: sessionStore ?? undefined, // Use Redis store if available, otherwise default to MemoryStore
        cookie: {
          secure: process.env['NODE_ENV'] === 'production',
          httpOnly: true,
          sameSite: process.env['NODE_ENV'] === 'production' ? 'strict' : 'lax',
          maxAge: 24 * 60 * 60 * 1000,
        },
      }),
    );

    logger.info('✅ Session middleware configured');
    return true;
  } catch (err) {
  const error = err instanceof Error ? err : new Error(String(err));
  logger.error('❌ Failed to setup session middleware:', error);
  throw error;
}

};

// ======================
// PASSPORT SETUP
// ======================

const setupPassport = () => {
  const passportInstance = initializePassport();
  app.use(passportInstance.initialize());
  app.use(passportInstance.session());
  logger.info('✅ Passport middleware configured');
};

// ======================
// TEST EMAIL ENDPOINT
// ======================

// Add a test email endpoint (protected in production)
if (process.env['NODE_ENV'] !== 'production') {
  app.post('/api/test-email', async (req: Request, res: Response) => {
    try {
      const { to = process.env['EMAIL_USER'], template = 'welcome' } = req.body;
      let result;

      switch (template) {
        case 'verification':
          result = await emailService.sendVerificationEmail({
            to,
            verificationToken: 'test-token-123',
            userName: 'Test User',
          });
          break;
        case 'welcome':
          result = await emailService.sendWelcomeEmail(to, 'Test User');
          break;
        case 'password-reset':
          result = await emailService.sendPasswordResetEmail({
            to,
            resetToken: 'test-reset-token-123',
            userName: 'Test User',
          });
          break;
        default:
          result = await emailService.sendEmail({
            to,
            subject: 'Test Email from Dev-Agency',
            text: 'This is a test email from Dev-Agency backend.',
            html: '<h1>Test Email</h1><p>This is a test email from Dev-Agency backend.</p>',
          });
      }

      res.json({
        success: true,
        message: 'Test email sent',
        result,
        emailStatus: emailService.getStatus(),
      });
    } catch (err) {
      const error = err instanceof Error ? err : new Error(String(err));
      res.status(500).json({
        success: false,
        error: error.message,
      });
    }
  });

  // Get email service status
  app.get('/api/email-status', (_req: Request, res: Response) => {
    res.json({
      success: true,
      status: emailService.getStatus(),
    });
  });
}

// ======================
// ROUTE MOUNTING
// ======================

// Mount API routes
app.use('/api/auth', authRoutes);
app.use('/api/oauth', oauthRoutes);

// Health check routes
app.get('/api/health', (_req: Request, res: Response) => {
  res.json({
    status: 'healthy',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    services: {
      database: 'connected',
      email: emailService.getStatus().isConnected
        ? 'connected'
        : 'disconnected',
    },
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

// Passport Google OAuth routes
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
app.get('/api/protected', (req: Request, res: Response) => {
  res.json({
    success: true,
    user: (req as any).user,
  });
});

// ======================
// 404 HANDLER
// ======================

app.use((req: Request, res: Response) => {
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
  try {
    logger.info('🚀 Starting server initialization...');

    // Initialize services in sequence
    await initializeDatabase();
    await initializeEmailService();
    await setupSessionMiddleware();
    setupPassport();

    // Start server
    app.listen(PORT, () => {
      logger.info(`✅ Server running on port ${PORT}`);

      // Log mounted routes
      console.log('\n📋 Mounted Routes:');
      console.log('├── /api/auth/*');
      console.log('├── /api/oauth/*');
      console.log('├── /api/health');
      console.log('├── /api/health/db');
      console.log('├── /api/auth/google');
      console.log('└── /api/auth/google/callback');

      if (process.env['NODE_ENV'] !== 'production') {
        console.log('├── /api/test-email (POST)');
        console.log('└── /api/email-status (GET)');
      }

      // Log email service status
      const emailStatus = emailService.getStatus();
      console.log('\n📧 Email Service:');
      console.log(`├── Service: ${emailStatus.service}`);
      console.log(
        `├── From: ${emailStatus.from.name} <${emailStatus.from.address}>`,
      );
      console.log(
        `└── Status: ${emailStatus.isConnected ? '✅ Connected' : '❌ Disconnected'}`,
      );
    });
  } catch (err) {
  const error = err instanceof Error ? err : new Error(String(err));
  logger.error('❌ Failed to start server:', error);
  process.exit(1);
}

};

// Start the server
startServer().catch((error) => {
  logger.error('❌ Unhandled error in startServer:', error);
  process.exit(1);
});

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
