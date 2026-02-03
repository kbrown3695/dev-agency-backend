import { Request, Response, NextFunction } from 'express';
import passport from 'passport';
import { Strategy as GoogleStrategy, Profile } from 'passport-google-oauth20';
import jwt from 'jsonwebtoken';
import prisma from '../config/db.js';
import crypto from 'crypto';
import logger from '../utils/logger.js';

// Generate JWT token
export const generateToken = (user: any): string => {
  const payload = {
    id: user.id,
    email: user.email,
    name: user.displayName || `${user.firstName} ${user.lastName}`,
    role: user.role,
    emailVerified: user.emailVerified,
    isOAuth: true,
    provider: 'google',
  };

  const jwtSecret = process.env['JWT_SECRET'] || 'fallback-secret';
  const jwtExpiresIn = process.env['JWT_EXPIRES_IN'] || '7d';

  return jwt.sign(payload, jwtSecret, {
    expiresIn: jwtExpiresIn,
    issuer: 'dev-agency-backend',
    subject: user.id,
  } as jwt.SignOptions);
};

// Initialize Google Strategy
export const initializeGoogleStrategy = (): void => {
  const clientID = process.env['GOOGLE_CLIENT_ID'];
  const clientSecret = process.env['GOOGLE_CLIENT_SECRET'];
  const callbackURL =
    process.env['GOOGLE_CALLBACK_URL'] || '/api/auth/google/callback';

  if (!clientID || !clientSecret) {
    logger.warn('Google OAuth credentials not configured');
    return;
  }

  passport.use(
    new GoogleStrategy(
      {
        clientID,
        clientSecret,
        callbackURL,
        passReqToCallback: true,
      },
      async (
        _req: Request, // Prefix with underscore to indicate it's intentionally unused
        _accessToken: string, // Prefix with underscore
        _refreshToken: string, // Prefix with underscore
        _params: any, // Prefix with underscore
        profile: Profile,
        done: (error: any, user?: any) => void,
      ) => {
        try {
          const email = profile.emails?.[0]?.value;

          if (!email) {
            return done(new Error('No email found in Google profile'), null);
          }

          let user = await prisma.user.findUnique({
            where: { email },
            include: { vendorProfile: true },
          });

          const userData: any = {
            email: email.toLowerCase(),
            firstName: profile.name?.givenName || null,
            lastName: profile.name?.familyName || null,
            displayName: profile.displayName || null,
            avatarUrl: profile.photos?.[0]?.value || null,
            googleId: profile.id,
            oauthProvider: 'google',
            oauthProviderId: profile.id,
            lastLogin: new Date(),
            emailVerified: (profile as any)._json?.email_verified || true,
            isActive: true,
          };

          if (user) {
            // Update existing user
            const updateData: any = {
              ...userData,
              updatedAt: new Date(),
            };

            user = await prisma.user.update({
              where: { id: user.id },
              data: updateData,
              include: { vendorProfile: true },
            });
          } else {
            // Create new user
            user = await prisma.user.create({
              data: {
                ...userData,
                passwordHash: crypto.randomBytes(32).toString('hex'),
                role: 'USER',
                isBuyer: true,
                isVendor: false,
                isSponsor: false,
              },
              include: { vendorProfile: true },
            });

            logger.info('New user created via Google OAuth:', {
              userId: user.id,
              email: user.email,
            });
          }

          // Generate token
          const token = generateToken(user);
          done(null, { user, token });
        } catch (error: any) {
          logger.error('Google OAuth error:', error);
          done(error, null);
        }
      },
    ),
  );
};

// Serialize user
passport.serializeUser((user: any, done) => {
  done(null, user.id);
});

// Deserialize user
passport.deserializeUser(async (id: string, done) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id },
      include: { vendorProfile: true },
    });

    if (!user) {
      return done(new Error('User not found'), null);
    }

    // Create a properly typed user object that matches Express.User interface
    const authUser = {
      id: user.id,
      email: user.email,
      role: user.role,
      firstName: user.firstName || '', // Convert null to empty string
      lastName: user.lastName || null,
      displayName: user.displayName || null,
      avatarUrl: user.avatarUrl || null,
      location: user.location || null,
      phone: user.phone || null,
      emailVerified: user.emailVerified,
      isActive: user.isActive,
      lastLogin: user.lastLogin,
      // Add vendorProfile as an additional property
      vendorProfile: user.vendorProfile,
    };

    done(null, authUser);
  } catch (error: any) {
    done(error, null);
  }
});

// Check if OAuth is configured
export const requireOAuthConfig = (
  _req: Request, // Prefix with underscore
  res: Response,
  next: NextFunction,
): void => {
  const clientID = process.env['GOOGLE_CLIENT_ID'];
  const clientSecret = process.env['GOOGLE_CLIENT_SECRET'];

  if (!clientID || !clientSecret) {
    res.status(501).json({
      success: false,
      error: 'OAuth is not configured',
    });
    return;
  }

  next();
};

// Link Google account middleware
export const linkGoogleAccount = async (
  req: Request,
  res: Response,
): Promise<void> => {
  try {
    const userId = (req as any).user?.id;
    const { googleToken } = req.body;

    if (!userId) {
      res.status(401).json({
        success: false,
        error: 'Authentication required',
      });
      return;
    }

    if (!googleToken) {
      res.status(400).json({
        success: false,
        error: 'Google token is required',
      });
      return;
    }

    // Verify Google token
    const { OAuth2Client } = await import('google-auth-library');
    const client = new OAuth2Client(process.env['GOOGLE_CLIENT_ID'] as string);

    const ticket = await client.verifyIdToken({
      idToken: googleToken,
      audience: process.env['GOOGLE_CLIENT_ID'] as string,
    });

    const payload = ticket.getPayload();

    if (!payload) {
      res.status(401).json({
        success: false,
        error: 'Invalid Google token',
      });
      return;
    }

    const googleId = payload.sub;
    const email = payload.email;

    if (!email) {
      res.status(400).json({
        success: false,
        error: 'No email found in Google token',
      });
      return;
    }

    // Check if Google account is already linked
    const existingUser = await prisma.user.findFirst({
      where: {
        OR: [{ googleId: googleId }, { email: email }],
      },
    });

    if (existingUser && existingUser.id !== userId) {
      res.status(409).json({
        success: false,
        error: 'Google account already linked to another user',
      });
      return;
    }

    // Link Google account
    const updateData: any = {
      updatedAt: new Date(),
    };

    // Add OAuth fields if they exist in schema
    updateData.googleId = googleId;
    updateData.oauthProvider = 'google';
    updateData.oauthProviderId = googleId;
    updateData.emailVerified = payload.email_verified || true;

    if (payload.picture) {
      updateData.avatarUrl = payload.picture;
    }

    await prisma.user.update({
      where: { id: userId },
      data: updateData,
    });

    logger.info('Google account linked:', { userId, googleId });

    res.status(200).json({
      success: true,
      message: 'Google account linked successfully',
    });
  } catch (error: any) {
    logger.error('Failed to link Google account:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to link Google account',
    });
  }
};

// Unlink Google account
export const unlinkGoogleAccount = async (
  req: Request,
  res: Response,
): Promise<void> => {
  try {
    const userId = (req as any).user?.id;

    if (!userId) {
      res.status(401).json({
        success: false,
        error: 'Authentication required',
      });
      return;
    }

    const user = await prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user || !(user as any).googleId) {
      res.status(400).json({
        success: false,
        error: 'Google account not linked',
      });
      return;
    }

    // Check if user has password (not relying only on OAuth)
    const userWithPassword = user as any;
    if (userWithPassword.passwordHash === 'oauth-google') {
      res.status(400).json({
        success: false,
        error: 'Cannot unlink Google account. Please set a password first.',
      });
      return;
    }

    // Unlink Google account
    const updateData: any = {
      updatedAt: new Date(),
      googleId: null,
    };

    // Remove OAuth provider fields
    if ((user as any).oauthProvider === 'google') {
      updateData.oauthProvider = null;
      updateData.oauthProviderId = null;
    }

    // Remove avatar if it's from Google
    if (user.avatarUrl?.includes('googleusercontent.com')) {
      updateData.avatarUrl = null;
    }

    await prisma.user.update({
      where: { id: userId },
      data: updateData,
    });

    logger.info('Google account unlinked:', { userId });

    res.status(200).json({
      success: true,
      message: 'Google account unlinked successfully',
    });
  } catch (error: any) {
    logger.error('Failed to unlink Google account:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to unlink Google account',
    });
  }
};

// Initialize passport
export const initializePassport = (): passport.PassportStatic => {
  initializeGoogleStrategy();
  return passport;
};
