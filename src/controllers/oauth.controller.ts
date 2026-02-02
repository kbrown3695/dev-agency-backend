import { Request, Response } from 'express';
import prisma from '../config/db.js';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { OAuth2Client } from 'google-auth-library';
import logger from '../utils/logger.js';

interface GoogleTokenPayload {
  sub: string;
  email: string;
  email_verified: boolean;
  name?: string;
  given_name?: string;
  family_name?: string;
  picture?: string;
}

interface UserWithVendorProfile {
  id: string;
  email: string;
  passwordHash: string;
  firstName: string | null;
  lastName: string | null;
  displayName: string | null;
  avatarUrl: string | null;
  bio: string | null;
  website: string | null;
  location: string | null;
  phone: string | null;
  oauthProvider: string | null;
  oauthProviderId: string | null;
  oauthAccessToken: string | null;
  oauthRefreshToken: string | null;
  oauthTokenExpiry: Date | null;
  googleId: string | null;
  emailVerified: boolean;
  verificationToken: string | null;
  verificationExpires: string | null;
  resetToken: string | null;
  resetExpires: string | null;
  isActive: boolean;
  role: 'USER' | 'ADMIN' | 'MODERATOR';
  isVendor: boolean;
  isBuyer: boolean;
  isSponsor: boolean;
  createdAt: Date;
  updatedAt: Date;
  lastLogin: Date | null;
  vendorProfile: {
    id: string;
    userId: string;
    companyName: string;
    companyLogo: string | null;
    description: string | null;
    services: string[];
    industries: string[];
    technologies: string[];
    hourlyRate: number | null;
    minProjectSize: number | null;
    employeeCount: number | null;
    foundedYear: number | null;
    contactEmail: string | null;
    contactPhone: string | null;
    address: string | null;
    country: string | null;
    website: string | null;
    linkedin: string | null;
    github: string | null;
    twitter: string | null;
    totalProjects: number;
    completedProjects: number;
    rating: number;
    reviewCount: number;
    isVerified: boolean;
    isFeatured: boolean;
    isListed: boolean;
    listingExpires: string | null;
    createdAt: Date;
    updatedAt: Date;
  } | null;
}

export class OAuthController {
  // Verify Google token and login/register
  static async verifyGoogleToken(req: Request, res: Response): Promise<void> {
    try {
      const { token, redirectUri } = req.body;

      if (!token) {
        res.status(400).json({
          success: false,
          error: 'Google token is required',
          code: 'MISSING_TOKEN',
        });
        return;
      }

      const googleClientId = process.env['GOOGLE_CLIENT_ID'];
      const googleClientSecret = process.env['GOOGLE_CLIENT_SECRET'];

      if (!googleClientId || !googleClientSecret) {
        res.status(500).json({
          success: false,
          error: 'Google OAuth not configured',
          code: 'OAUTH_NOT_CONFIGURED',
        });
        return;
      }

      // Verify token with Google
      const client = new OAuth2Client(
        googleClientId,
        googleClientSecret,
        redirectUri || 'postmessage',
      );

      const ticket = await client.verifyIdToken({
        idToken: token,
        audience: googleClientId,
      });

      const payload = ticket.getPayload() as GoogleTokenPayload;
      if (!payload) {
        res.status(400).json({
          success: false,
          error: 'Invalid Google token',
          code: 'INVALID_TOKEN',
        });
        return;
      }

      const {
        sub: googleId,
        email,
        email_verified,
        name,
        given_name,
        family_name,
        picture,
      } = payload;

      // Normalize email
      const normalizedEmail = email.toLowerCase();

      // Find or create user
      let user = (await prisma.user.findUnique({
        where: { email: normalizedEmail },
        include: { vendorProfile: true },
      })) as UserWithVendorProfile | null;

      if (user) {
        // Update existing user
        const updateData: any = {
          lastLogin: new Date(),
          updatedAt: new Date(),
        };

        // Link Google ID if not already linked
        if (!user.googleId) {
          updateData.googleId = googleId;
          updateData.oauthProvider = 'google';
          updateData.oauthProviderId = googleId;
        }

        // Update avatar if from Google
        if (
          picture &&
          (!user.avatarUrl || user.avatarUrl?.includes('googleusercontent.com'))
        ) {
          updateData.avatarUrl = picture;
        }

        // Update name if from Google and current is empty
        if (name && !user.displayName) {
          updateData.displayName = name;
        }
        if (given_name && !user.firstName) {
          updateData.firstName = given_name;
        }
        if (family_name && !user.lastName) {
          updateData.lastName = family_name;
        }

        if (Object.keys(updateData).length > 0) {
          user = (await prisma.user.update({
            where: { id: user.id },
            data: updateData,
            include: { vendorProfile: true },
          })) as UserWithVendorProfile;
        }

        logger.info('Google login for existing user:', {
          userId: user.id,
          email,
        });
      } else {
        // Create new user
        const userData = {
          email: normalizedEmail,
          firstName: given_name || null,
          lastName: family_name || null,
          displayName: name || email.split('@')[0] || null,
          avatarUrl: picture || null,
          passwordHash: crypto.randomBytes(32).toString('hex'),
          emailVerified: email_verified || false,
          googleId: googleId,
          oauthProvider: 'google',
          oauthProviderId: googleId,
          role: 'USER' as const,
          isActive: true,
          isBuyer: true,
          isVendor: false,
          isSponsor: false,
        };

        user = (await prisma.user.create({
          data: userData,
          include: { vendorProfile: true },
        })) as UserWithVendorProfile;

        logger.info('New user created via Google:', { userId: user.id, email });

        // Try to send welcome email if email service is available
        try {
          const emailServiceModule =
            await import('../services/email.service.js');
          const emailService =
            emailServiceModule.emailService || emailServiceModule.default;

          if (emailService && emailService.sendWelcomeEmail) {
            await emailService.sendWelcomeEmail(
              user.email,
              user.displayName || user.email,
            );
          }
        } catch (emailError: any) {
          logger.warn('Failed to send welcome email:', {
            error: emailError.message || 'Email service not available',
          });
        }
      }

      // Generate JWT token
      const jwtSecret = process.env['JWT_SECRET'] || 'fallback-secret';
      const jwtExpiresIn = process.env['JWT_EXPIRES_IN'] || '7d';

      const jwtToken = jwt.sign(
        {
          id: user.id,
          email: user.email,
          name: user.displayName,
          role: user.role,
          emailVerified: user.emailVerified,
          isOAuth: true,
          provider: 'google',
        },
        jwtSecret,
        {
          expiresIn: jwtExpiresIn,
          issuer: 'dev-agency-backend',
          subject: user.id,
        } as jwt.SignOptions,
      );

      // Create session
      const sessionTokenHash = crypto
        .createHash('sha256')
        .update(jwtToken)
        .digest('hex');

      try {
        await prisma.session.create({
          data: {
            userId: user.id,
            token: sessionTokenHash,
            expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
            userAgent: req.get('User-Agent') || 'Google OAuth',
            ipAddress: req.ip || '127.0.0.1',
          },
        });
      } catch (sessionError: any) {
        logger.warn('Failed to create session record:', {
          error: sessionError.message,
        });
      }

      // Set cookie
      res.cookie('auth_token', jwtToken, {
        httpOnly: true,
        secure: process.env['NODE_ENV'] === 'production',
        sameSite: 'strict',
        maxAge: 24 * 60 * 60 * 1000,
      });

      res.json({
        success: true,
        message: 'Google authentication successful',
        user: {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          displayName: user.displayName,
          avatarUrl: user.avatarUrl,
          role: user.role,
          emailVerified: user.emailVerified,
          vendorProfile: user.vendorProfile,
          googleId: user.googleId,
        },
        token: jwtToken,
        isOAuth: true,
        code: 'GOOGLE_AUTH_SUCCESS',
      });
    } catch (error: any) {
      logger.error('Google token verification error:', error);

      if (error.message.includes('Token used too late')) {
        res.status(400).json({
          success: false,
          error: 'Google token has expired',
          code: 'TOKEN_EXPIRED',
        });
        return;
      }

      res.status(500).json({
        success: false,
        error: 'Failed to authenticate with Google',
        code: 'GOOGLE_AUTH_FAILED',
        details:
          process.env['NODE_ENV'] === 'development' ? error.message : undefined,
      });
    }
  }

  // Get OAuth configuration for frontend
  static async getOAuthConfig(_req: Request, res: Response): Promise<void> {
    try {
      const config = {
        google: {
          enabled: !!process.env['GOOGLE_CLIENT_ID'],
          clientId: process.env['GOOGLE_CLIENT_ID'],
          scope: 'profile email',
          redirectUri:
            process.env['GOOGLE_REDIRECT_URI'] ||
            `${process.env['FRONTEND_URL']}/oauth/callback`,
        },
      };

      res.json({
        success: true,
        config,
      });
    } catch (error: any) {
      logger.error('Failed to get OAuth config:', error);
      res.status(500).json({
        success: false,
        error: 'Failed to get OAuth configuration',
      });
    }
  }

  // Unlink Google account
  static async unlinkGoogleAccount(req: Request, res: Response): Promise<void> {
    try {
      const userId = (req as any).user?.id;

      if (!userId) {
        res.status(401).json({
          success: false,
          error: 'Authentication required',
          code: 'NOT_AUTHENTICATED',
        });
        return;
      }

      const user = (await prisma.user.findUnique({
        where: { id: userId },
      })) as UserWithVendorProfile | null;

      if (!user) {
        res.status(404).json({
          success: false,
          error: 'User not found',
          code: 'USER_NOT_FOUND',
        });
        return;
      }

      // Only remove Google-related data
      const updateData: any = {
        updatedAt: new Date(),
        googleId: null,
      };

      // Also remove other OAuth fields if they exist
      if (user.oauthProvider === 'google') {
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

      res.json({
        success: true,
        message: 'Google account unlinked successfully',
        code: 'GOOGLE_UNLINKED',
      });
    } catch (error: any) {
      logger.error('Unlink Google account error:', error);
      res.status(500).json({
        success: false,
        error: 'Failed to unlink Google account',
        code: 'UNLINK_FAILED',
      });
    }
  }
}
