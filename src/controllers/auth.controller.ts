// src/controllers/auth.controller.ts
import { Request, Response } from 'express';
import prisma from '../config/db.js';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { emailService } from '../services/email.service.js';
import { generateToken } from '../middlewares/auth.middleware.js';

// Import Request from middleware
// import { Request } from '../middlewares/auth.middleware.js';

// Helper functions
const hashPassword = async (password: string): Promise<string> => {
  return bcrypt.hash(password, 12);
};

const validatePassword = (password: string): string[] => {
  const errors: string[] = [];
  if (password.length < 8)
    errors.push('Password must be at least 8 characters long');
  if (!/(?=.*[a-z])/.test(password))
    errors.push('Password must contain at least one lowercase letter');
  if (!/(?=.*[A-Z])/.test(password))
    errors.push('Password must contain at least one uppercase letter');
  if (!/(?=.*\d)/.test(password))
    errors.push('Password must contain at least one number');
  if (!/(?=.*[@$!%*?&])/.test(password))
    errors.push(
      'Password must contain at least one special character (@$!%*?&)',
    );
  return errors;
};

const isValidEmail = (email: string): boolean => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

// ==================== REGISTRATION ====================

export const register = async (req: Request, res: Response): Promise<void> => {
  try {
    const {
      email,
      password,
      firstName,
      lastName,
      displayName,
      phone,
      location,
    } = req.body;

    console.log('Registration attempt:', { email, firstName, lastName });

    // Validation
    if (!email || !password) {
      res.status(400).json({
        success: false,
        error: 'Email and password are required',
      });
      return;
    }

    if (!isValidEmail(email)) {
      res.status(400).json({
        success: false,
        error: 'Please provide a valid email address',
      });
      return;
    }

    const passwordErrors = validatePassword(password);
    if (passwordErrors.length > 0) {
      res.status(400).json({
        success: false,
        error: 'Password does not meet requirements',
        details: passwordErrors,
      });
      return;
    }

    // Check if user already exists
    const existingUser = await prisma.user.findUnique({
      where: { email: email.toLowerCase() },
    });

    if (existingUser) {
      res.status(409).json({
        success: false,
        error: 'User already exists with this email',
      });
      return;
    }

    // Hash password and generate verification token
    const passwordHash = await hashPassword(password);
    const verificationToken = crypto.randomBytes(32).toString('hex');
    const verificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);

    // Create user
    const user = await prisma.user.create({
      data: {
        email: email.toLowerCase(),
        passwordHash,
        firstName: firstName?.trim(),
        lastName: lastName?.trim(),
        displayName: displayName?.trim() || `${firstName} ${lastName}`.trim(),
        phone,
        location,
        verificationToken,
        verificationExpires: verificationExpires.toISOString(),
        role: 'USER',
        isBuyer: true,
        isActive: true,
      },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        displayName: true,
        role: true,
        isActive: true,
        emailVerified: true,
        createdAt: true,
      },
    });

    // Send verification email
    try {
      await emailService.sendVerificationEmail({
        to: user.email,
        verificationToken,
        userName: user.displayName || user.firstName || 'User',
      });
      console.log('Verification email sent to:', user.email);
    } catch (emailError) {
      console.error('Failed to send verification email:', emailError);
    }

    // Send welcome email
    try {
      await emailService.sendWelcomeEmail(
        user.email,
        user.displayName || user.firstName || 'User',
      );
      console.log('Welcome email sent to:', user.email);
    } catch (emailError) {
      console.error('Failed to send welcome email:', emailError);
    }

    // Generate JWT token
    const tokenData = generateToken(user);

    // Create session
    await prisma.session.create({
      data: {
        userId: user.id,
        token: tokenData.token,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
        userAgent: req.get('User-Agent')?.substring(0, 500) || 'Unknown',
        ipAddress: req.ip || req.connection.remoteAddress || 'Unknown',
      },
    });

    // Create security log - FIXED: Convert undefined to null
    await prisma.securityLog.create({
      data: {
        userId: user.id,
        action: 'REGISTRATION',
        ipAddress: req.ip || req.connection.remoteAddress || null,
        userAgent: req.get('User-Agent') || null,
        metadata: {
          method: 'email',
          userAgent: req.get('User-Agent') || null,
        },
      },
    });

    // Set secure cookie if needed
    res.cookie('auth_token', tokenData.token, {
      httpOnly: true,
      secure: process.env['NODE_ENV'] === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    res.status(201).json({
      success: true,
      message:
        'User registered successfully. Please check your email to verify your account.',
      data: {
        user,
        token: tokenData.token,
      },
      requiresVerification: true,
    });
  } catch (error: any) {
    console.error('Registration error:', error);

    if (error.code === 'P2002') {
      res.status(409).json({
        success: false,
        error: 'User already exists with this email',
      });
      return;
    }

    res.status(500).json({
      success: false,
      error: 'Failed to register user',
      details:
        process.env['NODE_ENV'] === 'development' ? error.message : undefined,
    });
  }
};

// ==================== LOGIN ====================

export const login = async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
      res.status(400).json({
        success: false,
        error: 'Email and password are required',
      });
      return;
    }

    if (!isValidEmail(email)) {
      res.status(400).json({
        success: false,
        error: 'Please provide a valid email address',
      });
      return;
    }

    const normalizedEmail = email.toLowerCase();

    // Find user
    const user = await prisma.user.findFirst({
      where: {
        email: normalizedEmail,
        isActive: true,
      },
      include: {
        vendorProfile: true,
      },
    });

    if (!user) {
      // Simulate password check for timing attack prevention
      await bcrypt.compare(
        password,
        '$2b$12$fakeHashForTimingAttackPrevention',
      );

      res.status(401).json({
        success: false,
        error: 'Invalid email or password',
      });
      return;
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.passwordHash);
    if (!isValidPassword) {
      res.status(401).json({
        success: false,
        error: 'Invalid email or password',
      });
      return;
    }

    // Generate JWT token
    const tokenData = generateToken(user);

    // Create session
    await prisma.session.create({
      data: {
        userId: user.id,
        token: tokenData.token,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
        userAgent: req.get('User-Agent')?.substring(0, 500) || 'Unknown',
        ipAddress: req.ip || req.connection.remoteAddress || 'Unknown',
      },
    });

    // Update last login
    await prisma.user.update({
      where: { id: user.id },
      data: { lastLogin: new Date() },
    });

    // Create security log - FIXED: Convert undefined to null
    await prisma.securityLog.create({
      data: {
        userId: user.id,
        action: 'LOGIN_SUCCESS',
        ipAddress: req.ip || req.connection.remoteAddress || null,
        userAgent: req.get('User-Agent') || null,
        metadata: {
          method: 'email',
          userAgent: req.get('User-Agent') || null,
        },
      },
    });

    // Set secure cookie
    res.cookie('auth_token', tokenData.token, {
      httpOnly: true,
      secure: process.env['NODE_ENV'] === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    // Prepare user response data
    const userResponse = {
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      displayName: user.displayName,
      role: user.role,
      isVendor: user.isVendor,
      isBuyer: user.isBuyer,
      isSponsor: user.isSponsor,
      emailVerified: user.emailVerified,
      isActive: user.isActive,
      avatarUrl: user.avatarUrl,
      phone: user.phone,
      location: user.location,
      lastLogin: user.lastLogin,
      createdAt: user.createdAt,
      vendorProfile: user.vendorProfile,
    };

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        user: userResponse,
        token: tokenData.token,
      },
    });
  } catch (error: any) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to login',
      details:
        process.env['NODE_ENV'] === 'development' ? error.message : undefined,
    });
  }
};

// ==================== LOGOUT ====================

export const logout = async (
  req: Request,
  res: Response,
): Promise<void> => {
  try {
    // Extract token from request
    const authHeader = req.headers['authorization'];
    const token = authHeader?.split(' ')[1] || req.cookies?.auth_token;

    if (token && req.user?.id) {
      // Delete session
      await prisma.session.deleteMany({
        where: {
          userId: req.user.id,
          token: token,
        },
      });

      // Create security log - FIXED: Convert undefined to null
      await prisma.securityLog.create({
        data: {
          userId: req.user.id,
          action: 'LOGOUT',
          ipAddress: req.ip || req.connection.remoteAddress || null,
          userAgent: req.get('User-Agent') || null,
          metadata: {},
        },
      });
    }

    // Clear the cookie
    res.clearCookie('auth_token');

    res.json({
      success: true,
      message: 'Logged out successfully',
    });
  } catch (error: any) {
    console.error('Logout error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to logout',
    });
  }
};

// ==================== CURRENT USER ====================

export const getCurrentUser = async (
  req: Request,
  res: Response,
): Promise<void> => {
  try {
    if (!req.user) {
      res.status(401).json({
        success: false,
        error: 'Authentication required',
      });
      return;
    }

    // Use only include, not select and include together
    const user = await prisma.user.findUnique({
      where: { id: req.user.id },
      include: {
        vendorProfile: true,
      },
    });

    if (!user) {
      res.status(404).json({
        success: false,
        error: 'User not found',
      });
      return;
    }

    // Remove sensitive data
    const {
      passwordHash,
      resetToken,
      resetExpires,
      verificationToken,
      verificationExpires,
      ...safeUser
    } = user;

    res.json({
      success: true,
      data: { user: safeUser },
    });
  } catch (error: any) {
    console.error('Get current user error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch user data',
    });
  }
};

// ==================== EMAIL VERIFICATION ====================

export const verifyEmail = async (
  req: Request,
  res: Response,
): Promise<void> => {
  try {
    const { token } = req.query;

    if (!token || typeof token !== 'string') {
      res.status(400).json({
        success: false,
        error: 'Verification token is required',
      });
      return;
    }

    const user = await prisma.user.findFirst({
      where: {
        verificationToken: token,
        verificationExpires: { gt: new Date().toISOString() },
        isActive: true,
      },
    });

    if (!user) {
      res.status(400).json({
        success: false,
        error: 'Invalid or expired verification token',
      });
      return;
    }

    const updatedUser = await prisma.user.update({
      where: { id: user.id },
      data: {
        emailVerified: true,
        verificationToken: null,
        verificationExpires: null,
      },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        emailVerified: true,
        role: true,
        createdAt: true,
      },
    });

    // Send verification success email
    try {
      await emailService.sendVerificationSuccessEmail({
        to: updatedUser.email,
        userName: updatedUser.firstName || updatedUser.email,
      });
      console.log('Verification success email sent to:', updatedUser.email);
    } catch (emailError) {
      console.error('Failed to send verification success email:', emailError);
    }

    // Create security log - FIXED: Convert undefined to null
    await prisma.securityLog.create({
      data: {
        userId: user.id,
        action: 'EMAIL_VERIFIED',
        ipAddress: req.ip || req.connection.remoteAddress || null,
        userAgent: req.get('User-Agent') || null,
        metadata: {},
      },
    });

    res.json({
      success: true,
      message: 'Email verified successfully!',
      data: { user: updatedUser },
    });
  } catch (error: any) {
    console.error('Email verification error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to verify email',
    });
  }
};

export const resendVerificationEmail = async (
  req: Request,
  res: Response,
): Promise<void> => {
  try {
    const { email } = req.body;

    if (!email) {
      res.status(400).json({
        success: false,
        error: 'Email is required',
      });
      return;
    }

    if (!isValidEmail(email)) {
      res.status(400).json({
        success: false,
        error: 'Please provide a valid email address',
      });
      return;
    }

    const user = await prisma.user.findFirst({
      where: {
        email: email.toLowerCase(),
        isActive: true,
      },
      select: {
        id: true,
        email: true,
        firstName: true,
        emailVerified: true,
        verificationExpires: true,
      },
    });

    if (!user) {
      // Don't reveal if user exists for security
      res.json({
        success: true,
        message:
          'If an account exists with this email, a verification link has been sent.',
      });
      return;
    }

    if (user.emailVerified) {
      res.status(400).json({
        success: false,
        error: 'Email is already verified',
      });
      return;
    }

    // Check if we recently sent a verification email
    if (
      user.verificationExpires &&
      new Date(user.verificationExpires) > new Date(Date.now() - 5 * 60 * 1000)
    ) {
      res.status(429).json({
        success: false,
        error:
          'Verification email already sent recently. Please check your email or wait a few minutes.',
      });
      return;
    }

    const verificationToken = crypto.randomBytes(32).toString('hex');
    const verificationExpires = new Date(
      Date.now() + 24 * 60 * 60 * 1000,
    ).toISOString();

    await prisma.user.update({
      where: { id: user.id },
      data: { verificationToken, verificationExpires },
    });

    try {
      await emailService.sendVerificationEmail({
        to: user.email,
        verificationToken,
        userName: user.firstName || user.email,
      });
      console.log('Verification email resent to:', user.email);
    } catch (emailError) {
      console.error('Failed to resend verification email:', emailError);
    }

    res.json({
      success: true,
      message:
        'If an account exists with this email, a verification link has been sent.',
    });
  } catch (error: any) {
    console.error('Resend verification email error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to resend verification email',
    });
  }
};

// ==================== PASSWORD RESET ====================

export const requestPasswordReset = async (
  req: Request,
  res: Response,
): Promise<void> => {
  try {
    const { email } = req.body;

    if (!email) {
      res.status(400).json({
        success: false,
        error: 'Email is required',
      });
      return;
    }

    if (!isValidEmail(email)) {
      res.status(400).json({
        success: false,
        error: 'Please provide a valid email address',
      });
      return;
    }

    const normalizedEmail = email.toLowerCase();

    // Rate limiting
    const lastRequest = await prisma.user.findFirst({
      where: {
        email: normalizedEmail,
        resetExpires: { gt: new Date().toISOString() },
      },
    });

    if (lastRequest) {
      res.status(429).json({
        success: false,
        error: 'Please wait before requesting another reset',
      });
      return;
    }

    // Find user
    const user = await prisma.user.findFirst({
      where: {
        email: normalizedEmail,
        isActive: true,
      },
    });

    if (!user) {
      // Don't reveal if user exists for security
      // Simulate processing time
      await new Promise((resolve) =>
        setTimeout(resolve, 500 + Math.random() * 500),
      );

      res.json({
        success: true,
        message: 'If the email exists, a reset link has been sent',
      });
      return;
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetExpires = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 1 hour

    // Update user with reset token
    await prisma.user.update({
      where: { id: user.id },
      data: { resetToken, resetExpires },
    });

    // Send reset email
    try {
      await emailService.sendPasswordResetEmail({
        to: user.email,
        resetToken,
        userName: user.firstName || user.email,
      });
      console.log('Password reset email sent to:', user.email);
    } catch (emailError) {
      console.error('Failed to send password reset email:', emailError);
    }

    // Create security log - FIXED: Convert undefined to null
    await prisma.securityLog.create({
      data: {
        userId: user.id,
        action: 'PASSWORD_RESET_REQUESTED',
        ipAddress: req.ip || req.connection.remoteAddress || null,
        userAgent: req.get('User-Agent') || null,
        metadata: {},
      },
    });

    res.json({
      success: true,
      message: 'If the email exists, a reset link has been sent',
    });
  } catch (error: any) {
    console.error('Request password reset error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to process password reset request',
    });
  }
};

export const resetPassword = async (
  req: Request,
  res: Response,
): Promise<void> => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      res.status(400).json({
        success: false,
        error: 'Token and new password are required',
      });
      return;
    }

    const passwordErrors = validatePassword(newPassword);
    if (passwordErrors.length > 0) {
      res.status(400).json({
        success: false,
        error: 'Password does not meet requirements',
        details: passwordErrors,
      });
      return;
    }

    // Find user with valid reset token
    const user = await prisma.user.findFirst({
      where: {
        resetToken: token,
        resetExpires: { gt: new Date().toISOString() },
        isActive: true,
      },
    });

    if (!user) {
      res.status(400).json({
        success: false,
        error: 'Invalid or expired reset token',
      });
      return;
    }

    // Check if new password is same as current
    const isSamePassword = await bcrypt.compare(newPassword, user.passwordHash);
    if (isSamePassword) {
      res.status(400).json({
        success: false,
        error: 'New password must be different from current password',
      });
      return;
    }

    const newPasswordHash = await hashPassword(newPassword);

    await prisma.$transaction([
      // Update password and clear reset token
      prisma.user.update({
        where: { id: user.id },
        data: {
          passwordHash: newPasswordHash,
          resetToken: null,
          resetExpires: null,
        },
      }),
      // Delete all sessions for security
      prisma.session.deleteMany({
        where: { userId: user.id },
      }),
    ]);

    // Send password changed email
    try {
      await emailService.sendPasswordChangedEmail({
        to: user.email,
        userName: user.firstName || user.email,
      });
      console.log('Password change notification sent to:', user.email);
    } catch (emailError) {
      console.error('Failed to send password change notification:', emailError);
    }

    // Create security log - FIXED: Convert undefined to null
    await prisma.securityLog.create({
      data: {
        userId: user.id,
        action: 'PASSWORD_RESET_COMPLETED',
        ipAddress: req.ip || req.connection.remoteAddress || null,
        userAgent: req.get('User-Agent') || null,
        metadata: {},
      },
    });

    res.json({
      success: true,
      message: 'Password reset successfully',
    });
  } catch (error: any) {
    console.error('Reset password error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to reset password',
    });
  }
};

// ==================== CHANGE PASSWORD ====================

export const changePassword = async (
  req: Request,
  res: Response,
): Promise<void> => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!req.user) {
      res.status(401).json({
        success: false,
        error: 'Authentication required',
      });
      return;
    }

    if (!currentPassword || !newPassword) {
      res.status(400).json({
        success: false,
        error: 'Current password and new password are required',
      });
      return;
    }

    const passwordErrors = validatePassword(newPassword);
    if (passwordErrors.length > 0) {
      res.status(400).json({
        success: false,
        error: 'New password does not meet requirements',
        details: passwordErrors,
      });
      return;
    }

    // Get user with password hash
    const user = await prisma.user.findUnique({
      where: { id: req.user.id },
      select: { id: true, passwordHash: true, email: true, firstName: true },
    });

    if (!user) {
      res.status(404).json({
        success: false,
        error: 'User not found',
      });
      return;
    }

    const isCurrentPasswordValid = await bcrypt.compare(
      currentPassword,
      user.passwordHash,
    );
    if (!isCurrentPasswordValid) {
      res.status(400).json({
        success: false,
        error: 'Current password is incorrect',
      });
      return;
    }

    const isSamePassword = await bcrypt.compare(newPassword, user.passwordHash);
    if (isSamePassword) {
      res.status(400).json({
        success: false,
        error: 'New password must be different from current password',
      });
      return;
    }

    const newPasswordHash = await hashPassword(newPassword);

    await prisma.$transaction([
      // Update password
      prisma.user.update({
        where: { id: user.id },
        data: { passwordHash: newPasswordHash },
      }),
      // Delete all sessions except current one for security
      prisma.session.deleteMany({
        where: {
          userId: user.id,
          token: {
            not:
              req.headers.authorization?.split(' ')[1] ||
              req.cookies?.auth_token,
          },
        },
      }),
    ]);

    // Send password changed email
    try {
      await emailService.sendPasswordChangedEmail({
        to: user.email,
        userName: user.firstName || user.email,
      });
      console.log('Password change notification sent to:', user.email);
    } catch (emailError) {
      console.error('Failed to send password change email:', emailError);
    }

    // Create security log - FIXED: Convert undefined to null
    await prisma.securityLog.create({
      data: {
        userId: user.id,
        action: 'PASSWORD_CHANGED',
        ipAddress: req.ip || req.connection.remoteAddress || null,
        userAgent: req.get('User-Agent') || null,
        metadata: {},
      },
    });

    res.json({
      success: true,
      message: 'Password updated successfully',
    });
  } catch (error: any) {
    console.error('Change password error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to change password',
    });
  }
};

// ==================== UPDATE PROFILE ====================

export const updateProfile = async (
  req: Request,
  res: Response,
): Promise<void> => {
  try {
    if (!req.user) {
      res.status(401).json({
        success: false,
        error: 'Authentication required',
      });
      return;
    }

    const {
      firstName,
      lastName,
      displayName,
      avatarUrl,
      bio,
      website,
      location,
      phone,
      isVendor,
      isBuyer,
      isSponsor,
    } = req.body;

    // Check if email is being changed and if it's already taken
    if (req.body.email && req.body.email !== req.user.email) {
      const existingUser = await prisma.user.findFirst({
        where: {
          email: req.body.email.toLowerCase(),
          id: { not: req.user.id },
        },
      });

      if (existingUser) {
        res.status(400).json({
          success: false,
          error: 'Email already in use',
        });
        return;
      }
    }

    // Update user
    const updatedUser = await prisma.user.update({
      where: { id: req.user.id },
      data: {
        ...(firstName && { firstName: firstName.trim() }),
        ...(lastName && { lastName: lastName.trim() }),
        ...(displayName && { displayName: displayName.trim() }),
        ...(avatarUrl && { avatarUrl }),
        ...(bio && { bio }),
        ...(website && { website }),
        ...(location && { location }),
        ...(phone && { phone }),
        ...(req.body.email && { email: req.body.email.toLowerCase() }),
        ...(isVendor !== undefined && { isVendor }),
        ...(isBuyer !== undefined && { isBuyer }),
        ...(isSponsor !== undefined && { isSponsor }),
      },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        displayName: true,
        avatarUrl: true,
        bio: true,
        website: true,
        location: true,
        phone: true,
        role: true,
        isVendor: true,
        isBuyer: true,
        isSponsor: true,
        emailVerified: true,
        isActive: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    // Create security log - FIXED: Convert undefined to null
    await prisma.securityLog.create({
      data: {
        userId: req.user.id,
        action: 'PROFILE_UPDATED',
        ipAddress: req.ip || req.connection.remoteAddress || null,
        userAgent: req.get('User-Agent') || null,
        metadata: {},
      },
    });

    res.json({
      success: true,
      message: 'Profile updated successfully',
      data: { user: updatedUser },
    });
  } catch (error: any) {
    console.error('Update profile error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update profile',
    });
  }
};

// ==================== TOKEN REFRESH ====================

export const refreshToken = async (
  req: Request,
  res: Response,
): Promise<void> => {
  try {
    if (!req.user) {
      res.status(401).json({
        success: false,
        error: 'Authentication required',
      });
      return;
    }

    // Get fresh user data
    const user = await prisma.user.findUnique({
      where: { id: req.user.id },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        displayName: true,
        role: true,
        isActive: true,
        emailVerified: true,
      },
    });

    if (!user || !user.isActive) {
      res.status(401).json({
        success: false,
        error: 'User not found or account deactivated',
      });
      return;
    }

    // Generate new token
    const newTokenData = generateToken(user);

    // Update session with new token
    const oldToken =
      req.headers.authorization?.split(' ')[1] || req.cookies?.auth_token;

    if (oldToken) {
      await prisma.session.updateMany({
        where: {
          userId: user.id,
          token: oldToken,
        },
        data: {
          token: newTokenData.token,
          expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
          updatedAt: new Date(),
        },
      });
    }

    // Update cookie
    res.cookie('auth_token', newTokenData.token, {
      httpOnly: true,
      secure: process.env['NODE_ENV'] === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    // Create security log - FIXED: Convert undefined to null
    await prisma.securityLog.create({
      data: {
        userId: user.id,
        action: 'TOKEN_REFRESHED',
        ipAddress: req.ip || req.connection.remoteAddress || null,
        userAgent: req.get('User-Agent') || null,
        metadata: {},
      },
    });

    res.json({
      success: true,
      message: 'Token refreshed successfully',
      data: {
        token: newTokenData.token,
      },
    });
  } catch (error: any) {
    console.error('Token refresh error:', error);
    res.status(401).json({
      success: false,
      error: 'Failed to refresh token',
    });
  }
};

// ==================== ACCOUNT DEACTIVATION & REACTIVATION ====================

/**
 * User-initiated account deactivation
 */
export const deactivateAccount = async (
  req: Request,
  res: Response,
): Promise<void> => {
  try {
    if (!req.user) {
      res.status(401).json({
        success: false,
        error: 'Authentication required',
      });
      return;
    }

    const userId = req.user.id;

    // Verify user is active before deactivation
    const activeUser = await prisma.user.findFirst({
      where: {
        id: userId,
        isActive: true,
      },
    });

    if (!activeUser) {
      res.status(400).json({
        success: false,
        error: 'Account is already deactivated',
      });
      return;
    }

    // Transaction: Core user deactivation
    await prisma.$transaction(async (tx) => {
      // 1. Deactivate user account
      await tx.user.update({
        where: { id: userId },
        data: {
          isActive: false,
          deactivatedAt: new Date(),
          deactivatedBy: userId,
          deactivationType: 'user_initiated',
          updatedAt: new Date(),
        },
      });

      // 2. Delete all active sessions
      await tx.session.deleteMany({
        where: {
          userId,
          expiresAt: { gt: new Date() }, // Only delete active sessions
        },
      });

      // 3. Create security log - FIXED: Convert undefined to null
      await tx.securityLog.create({
        data: {
          userId: userId,
          action: 'ACCOUNT_DEACTIVATED',
          ipAddress: req.ip || req.connection.remoteAddress || null,
          userAgent: req.get('User-Agent') || null,
          metadata: {
            deactivationMethod: 'user_request',
            deactivationType: 'user_initiated',
            emailPreserved: true,
            canBeReactivated: true,
          },
        },
      });
    });

    // Send deactivation confirmation email
    try {
      const ipAddress = req.ip || req.connection.remoteAddress;
      const userAgent = req.get('User-Agent');

      // Build email options object, only including optional properties if they have values
      const emailOptions: {
        to: string;
        userName: string;
        deactivatedAt: Date;
        ipAddress?: string;
        userAgent?: string;
      } = {
        to: req.user.email,
        userName: req.user.displayName || req.user.firstName || 'User',
        deactivatedAt: new Date(),
      };

      // Only add optional properties if they exist
      if (ipAddress) emailOptions.ipAddress = ipAddress;
      if (userAgent) emailOptions.userAgent = userAgent;

      await emailService.sendDeactivationConfirmation(emailOptions);
      console.log('Deactivation confirmation sent to:', req.user.email);
    } catch (emailError) {
      console.error('Failed to send deactivation confirmation:', emailError);
    }

    // Clear the authentication cookie
    res.clearCookie('auth_token');

    res.json({
      success: true,
      message:
        'Account deactivated successfully. You can reactivate within 30 days.',
      data: {
        deactivatedAt: new Date().toISOString(),
        canBeReactivated: true,
        reactivationWindowDays: 30,
      },
    });
  } catch (error: any) {
    console.error('Deactivate account error:', error);

    // Log the error - FIXED: Handle optional userId
    await prisma.securityLog.create({
      data: {
        userId: req.user?.id || null,
        action: 'ACCOUNT_DEACTIVATION_FAILED',
        ipAddress: req.ip || req.connection.remoteAddress || null,
        userAgent: req.get('User-Agent') || null,
        metadata: {
          error: error.message,
          step: 'deactivation_process',
        },
      },
    });

    res.status(500).json({
      success: false,
      error: 'Failed to deactivate account. Please contact support.',
    });
  }
};

/**
 * Check account status (public endpoint - no auth required)
 */
export const checkAccountStatus = async (
  req: Request,
  res: Response,
): Promise<void> => {
  try {
    const { email } = req.body;

    // Enhanced email validation
    if (!email || typeof email !== 'string') {
      res.status(400).json({
        success: false,
        error: 'Valid email is required',
      });
      return;
    }

    const normalizedEmail = email.toLowerCase().trim();

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(normalizedEmail)) {
      res.status(400).json({
        success: false,
        error: 'Invalid email format',
      });
      return;
    }

    // Find user by email
    const user = await prisma.user.findFirst({
      where: {
        email: normalizedEmail,
      },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        displayName: true,
        isActive: true,
        emailVerified: true,
        deactivatedAt: true,
        deactivationType: true,
        deactivatedBy: true,
        lastLogin: true,
      },
    });

    // For security, don't reveal if email exists but is inactive
    if (!user) {
      res.json({
        success: true,
        data: {
          exists: false,
          active: false,
          deactivated: false,
          message: 'No account found with this email',
        },
      });
      return;
    }

    // Check if deactivated by admin
    let deactivatedByAdmin = false;
    let adminDetails = null;

    if (
      !user.isActive &&
      user.deactivatedAt &&
      user.deactivatedBy &&
      user.deactivatedBy !== user.id
    ) {
      deactivatedByAdmin = true;
      // Get admin details if available
      const adminUser = await prisma.user.findUnique({
        where: { id: user.deactivatedBy },
        select: {
          email: true,
          displayName: true,
        },
      });
      adminDetails = adminUser;
    }

    res.json({
      success: true,
      data: {
        exists: true,
        active: user.isActive,
        deactivated: !user.isActive,
        deactivatedAt: user.deactivatedAt,
        deactivationType: user.deactivationType,
        deactivatedByAdmin,
        adminDetails,
        emailVerified: user.emailVerified,
        lastLogin: user.lastLogin,
        canBeReactivated:
          !user.isActive &&
          user.deactivationType === 'user_initiated' &&
          (!user.deactivatedAt ||
            new Date(user.deactivatedAt) >
              new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)), // 30 days
        message: user.isActive ? 'Account is active' : 'Account is deactivated',
      },
    });
  } catch (error: any) {
    console.error('Check account status error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to check account status',
    });
  }
};

/**
 * Check authenticated user status and token validity
 */
export const checkUserStatus = async (
  req: Request,
  res: Response,
): Promise<void> => {
  try {
    if (!req.user) {
      res.status(401).json({
        success: false,
        error: 'Authentication required',
      });
      return;
    }

    const userId = req.user.id;
    const tokenEmail = req.user.email; // Email from the JWT token

    console.log('🔍 Checking user status for:', { userId, tokenEmail });

    const user = await prisma.user.findFirst({
      where: {
        id: userId,
      },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        displayName: true,
        role: true,
        isActive: true,
        deactivatedAt: true,
        deactivationType: true,
        deactivatedBy: true,
        emailVerified: true,
        isVendor: true,
        isBuyer: true,
        isSponsor: true,
        avatarUrl: true,
        phone: true,
        location: true,
        lastLogin: true,
        createdAt: true,
        updatedAt: true,
        preferences: true,
      },
    });

    if (!user) {
      res.status(404).json({
        success: false,
        error: 'User not found',
        needsTokenRefresh: true,
      });
      return;
    }

    // Check if token email matches current user email
    // This happens when user email was changed
    const needsTokenRefresh = tokenEmail !== user.email;

    if (needsTokenRefresh) {
      console.log('🔄 Token email mismatch:', {
        tokenEmail,
        currentEmail: user.email,
        userId,
      });
    }

    res.json({
      success: true,
      data: {
        user: {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          displayName: user.displayName,
          role: user.role,
          isActive: user.isActive,
          emailVerified: user.emailVerified,
          isVendor: user.isVendor,
          isBuyer: user.isBuyer,
          isSponsor: user.isSponsor,
          avatarUrl: user.avatarUrl,
          phone: user.phone,
          location: user.location,
          lastLogin: user.lastLogin,
          createdAt: user.createdAt,
          updatedAt: user.updatedAt,
          preferences: user.preferences,
        },
        needsTokenRefresh,
        isActive: user.isActive,
        status: user.isActive ? 'active' : 'deactivated',
        deactivatedAt: user.deactivatedAt,
        deactivationType: user.deactivationType,
        message: user.isActive ? 'Account is active' : 'Account is deactivated',
      },
    });
  } catch (error: any) {
    console.error('Check user status error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to check user status',
    });
  }
};

/**
 * Request reactivation for deactivated account
 */
export const requestReactivation = async (
  req: Request,
  res: Response,
): Promise<void> => {
  try {
    const { email } = req.body;

    if (!email) {
      res.status(400).json({
        success: false,
        error: 'Email is required',
      });
      return;
    }

    if (!isValidEmail(email)) {
      res.status(400).json({
        success: false,
        error: 'Please provide a valid email address',
      });
      return;
    }

    const normalizedEmail = email.toLowerCase();

    
    // Rate limiting: Check for recent reactivation requests
    const ipAddress = req.ip || req.connection.remoteAddress;

    const whereClause: {
      createdAt: { gte: Date };
      ipAddress?: string | null;
    } = {
      createdAt: {
        gte: new Date(Date.now() - 15 * 60 * 1000), // Last 15 minutes
      },
    };

    // Only add ipAddress filter if we have a value
    if (ipAddress) {
      whereClause.ipAddress = ipAddress;
    }

    const recentRequests = await prisma.securityLog.count({
      where: whereClause,
    });

    if (recentRequests >= 3) {
      res.status(429).json({
        success: false,
        error: 'Too many reactivation requests. Please wait 15 minutes.',
        code: 'REACTIVATION_RATE_LIMITED',
      });
      return;
    }

    // Find deactivated user
    const deactivatedUser = await prisma.user.findFirst({
      where: {
        email: normalizedEmail,
        isActive: false,
        deactivationType: 'user_initiated',
        deactivatedAt: {
          gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000), // Within last 30 days
        },
      },
    });

    if (!deactivatedUser) {
      // Don't reveal whether account exists for security
      // Log the attempt - FIXED: Remove 'path' from metadata
      await prisma.securityLog.create({
        data: {
          action: 'REACTIVATION_REQUEST_FAILED',
          ipAddress: req.ip || req.connection.remoteAddress || null,
          userAgent: req.get('User-Agent') || null,
          metadata: {
            email: normalizedEmail,
            reason: 'user_not_found_or_not_eligible',
          },
        },
      });

      res.json({
        success: true,
        message:
          'If a deactivated account exists with this email, a reactivation link has been sent.',
      });
      return;
    }

    // Check if user is already active (edge case)
    if (deactivatedUser.isActive) {
      res.status(400).json({
        success: false,
        error: 'Account is already active',
      });
      return;
    }

    const reactivationToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    // Store reactivation token in user record (reusing resetToken field)
    await prisma.user.update({
      where: { id: deactivatedUser.id },
      data: {
        resetToken: reactivationToken,
        resetExpires: expiresAt.toISOString(),
      },
    });

    // Log reactivation request - FIXED: Convert undefined to null
    await prisma.securityLog.create({
      data: {
        userId: deactivatedUser.id,
        action: 'REACTIVATION_REQUESTED',
        ipAddress: req.ip || req.connection.remoteAddress || null,
        userAgent: req.get('User-Agent') || null,
        metadata: {
          email: normalizedEmail,
          tokenGenerated: true,
          expiresAt: expiresAt.toISOString(),
        },
      },
    });

    // Send reactivation email
    try {
      await emailService.sendReactivationEmail({
        to: deactivatedUser.email,
        userName:
          deactivatedUser.displayName ||
          deactivatedUser.firstName ||
          deactivatedUser.email,
        reactivationToken,
        expiresAt,
      });
      console.log('Reactivation email sent to:', deactivatedUser.email);
    } catch (emailError) {
      console.error('Failed to send reactivation email:', emailError);

      // Log email failure - FIXED: Convert undefined to null
      await prisma.securityLog.create({
        data: {
          userId: deactivatedUser.id,
          action: 'REACTIVATION_EMAIL_FAILED',
          ipAddress: req.ip || req.connection.remoteAddress || null,
          userAgent: req.get('User-Agent') || null,
          metadata: {
            email: normalizedEmail,
            error:
              emailError instanceof Error
                ? emailError.message
                : 'Unknown error',
          },
        },
      });
    }

    res.json({
      success: true,
      message:
        'If a deactivated account exists with this email, a reactivation link has been sent.',
      data: {
        emailSent: true,
        expiresAt: expiresAt.toISOString(),
      },
    });
  } catch (error: any) {
    console.error('Request reactivation error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to process reactivation request',
    });
  }
};

/**
 * Complete reactivation with token and new password
 */
export const completeReactivation = async (
  req: Request,
  res: Response,
): Promise<void> => {
  try {
    const { token, newPassword } = req.body;
    const currentTime = new Date();

    if (!token || !newPassword) {
      res.status(400).json({
        success: false,
        error: 'Token and new password are required',
      });
      return;
    }

    const passwordErrors = validatePassword(newPassword);
    if (passwordErrors.length > 0) {
      res.status(400).json({
        success: false,
        error: 'Password does not meet requirements',
        details: passwordErrors,
      });
      return;
    }

    // Find user with valid reactivation token
    const user = await prisma.user.findFirst({
      where: {
        resetToken: token,
        resetExpires: { gt: currentTime.toISOString() },
        isActive: false,
        deactivationType: 'user_initiated',
      },
    });

    if (!user) {
      res.status(400).json({
        success: false,
        error: 'Invalid or expired reactivation token',
      });
      return;
    }

    // Check if reactivation is within allowed window (30 days)
    if (
      user.deactivatedAt &&
      new Date(user.deactivatedAt) <
        new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)
    ) {
      res.status(400).json({
        success: false,
        error: 'Reactivation window has expired. Please contact support.',
      });
      return;
    }

    const newPasswordHash = await hashPassword(newPassword);

    await prisma.$transaction(async (tx) => {
      // 1. Reactivate user account
      await tx.user.update({
        where: { id: user.id },
        data: {
          isActive: true,
          deactivatedAt: null,
          deactivatedBy: null,
          deactivationType: null,
          passwordHash: newPasswordHash,
          resetToken: null,
          resetExpires: null,
          lastLogin: currentTime,
          updatedAt: currentTime,
        },
      });

      // 2. Log the reactivation - FIXED: Convert undefined to null
      await tx.securityLog.create({
        data: {
          userId: user.id,
          action: 'ACCOUNT_REACTIVATED',
          ipAddress: req.ip || req.connection.remoteAddress || null,
          userAgent: req.get('User-Agent') || null,
          metadata: {
            reactivationMethod: 'token_based',
            originalDeactivation: user.deactivatedAt,
            emailPreserved: true,
          },
        },
      });
    });

    // Send reactivation success email
    try {
      await emailService.sendReactivationSuccessEmail({
        to: user.email,
        userName: user.displayName || user.firstName || user.email,
        reactivatedAt: currentTime,
      });
      console.log('Reactivation success email sent to:', user.email);
    } catch (emailError) {
      console.error('Failed to send reactivation success email:', emailError);
    }

    res.json({
      success: true,
      message:
        'Account reactivated successfully. You can now login with your new password.',
      data: {
        email: user.email,
        reactivatedAt: currentTime.toISOString(),
      },
    });
  } catch (error: any) {
    console.error('Complete reactivation error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to reactivate account',
    });
  }
};

/**
 * Admin: Deactivate user account
 */
export const adminDeactivateAccount = async (
  req: Request,
  res: Response,
): Promise<void> => {
  try {
    if (!req.user) {
      res.status(401).json({
        success: false,
        error: 'Authentication required',
      });
      return;
    }

    // FIXED: Access userId properly from params
    const userId = req.params['userId'];
    if (!userId || typeof userId !== 'string') {
      res.status(400).json({
        success: false,
        error: 'Valid user ID is required',
      });
      return;
    }

    const adminId = req.user.id;
    const currentTime = new Date();

    // Verify admin privileges
    const adminUser = await prisma.user.findUnique({
      where: { id: adminId },
      select: { role: true, displayName: true, email: true },
    });

    if (!adminUser || !['ADMIN', 'MODERATOR'].includes(adminUser.role)) {
      res.status(403).json({
        success: false,
        error: 'Unauthorized: Admin privileges required',
      });
      return;
    }

    const targetUser = await prisma.user.findUnique({
      where: { id: userId },
    });

    if (!targetUser) {
      res.status(404).json({
        success: false,
        error: 'User not found',
      });
      return;
    }

    if (targetUser.id === adminId) {
      res.status(400).json({
        success: false,
        error: 'Cannot deactivate your own admin account',
      });
      return;
    }

    // Check role hierarchy: Only admins can deactivate other admins
    if (targetUser.role === 'ADMIN' && adminUser.role !== 'ADMIN') {
      res.status(403).json({
        success: false,
        error: 'Only administrators can deactivate other admin accounts.',
      });
      return;
    }

    if (!targetUser.isActive) {
      res.status(400).json({
        success: false,
        error: 'User account is already deactivated',
      });
      return;
    }

    await prisma.$transaction(async (tx) => {
      // Deactivate user account
      await tx.user.update({
        where: { id: userId },
        data: {
          isActive: false,
          deactivatedAt: currentTime,
          deactivatedBy: adminId,
          deactivationType: 'admin',
          updatedAt: currentTime,
        },
      });

      // Delete all active sessions
      await tx.session.deleteMany({
        where: {
          userId,
          expiresAt: { gt: new Date() },
        },
      });

      // Log admin action - FIXED: Convert undefined to null
      await tx.securityLog.create({
        data: {
          userId: adminId,
          action: 'ADMIN_DEACTIVATED_ACCOUNT',
          ipAddress: req.ip || req.connection.remoteAddress || null,
          userAgent: req.get('User-Agent') || null,
          metadata: {
            targetUserId: userId,
            targetUserEmail: targetUser.email,
            adminEmail: adminUser.email,
            deactivationType: 'admin',
            canBeReactivated: true,
          },
        },
      });
    });

    // Send notification email to user
    try {
      await emailService.sendAdminDeactivationNotification({
        to: targetUser.email,
        userName:
          targetUser.displayName || targetUser.firstName || targetUser.email,
        deactivatedAt: currentTime,
        adminEmail: adminUser.email,
        adminName: adminUser.displayName || adminUser.email,
        reason: 'admin_action',
      });
      console.log('Admin deactivation notification sent to:', targetUser.email);
    } catch (emailError) {
      console.warn('Admin deactivation notification email failed:', emailError);
    }

    res.json({
      success: true,
      message: 'User account deactivated successfully by admin',
      data: {
        deactivatedUser: {
          id: userId,
          email: targetUser.email,
        },
        deactivatedAt: currentTime.toISOString(),
        deactivatedBy: {
          id: adminId,
          email: adminUser.email,
          name: adminUser.displayName,
        },
      },
    });
  } catch (error: any) {
    console.error('Admin deactivate account error:', error);

    // Log the error - FIXED: Handle req.params properly
    await prisma.securityLog.create({
      data: {
        userId: req.user?.id || null,
        action: 'ADMIN_DEACTIVATION_FAILED',
        ipAddress: req.ip || req.connection.remoteAddress || null,
        userAgent: req.get('User-Agent') || null,
        metadata: {
          error: error.message,
          targetUserId: req.params['userId'],
          step: 'admin_deactivation_process',
        },
      },
    });

    res.status(500).json({
      success: false,
      error: 'Failed to deactivate user account',
    });
  }
};

/**
 * Admin: Reactivate user account
 */
export const adminReactivateAccount = async (
  req: Request,
  res: Response,
): Promise<void> => {
  try {
    if (!req.user) {
      res.status(401).json({
        success: false,
        error: 'Authentication required',
      });
      return;
    }

    // FIXED: Access userId properly from params
    const userId = req.params['userId'];
    if (!userId || typeof userId !== 'string') {
      res.status(400).json({
        success: false,
        error: 'Valid user ID is required',
      });
      return;
    }

    const adminId = req.user.id;
    const currentTime = new Date();

    // Verify admin privileges
    const adminUser = await prisma.user.findUnique({
      where: { id: adminId },
      select: { role: true, displayName: true, email: true },
    });

    if (!adminUser || !['ADMIN', 'MODERATOR'].includes(adminUser.role)) {
      res.status(403).json({
        success: false,
        error: 'Unauthorized: Admin privileges required',
      });
      return;
    }

    const targetUser = await prisma.user.findUnique({
      where: { id: userId },
    });

    if (!targetUser) {
      res.status(404).json({
        success: false,
        error: 'User not found',
      });
      return;
    }

    if (targetUser.isActive) {
      res.status(400).json({
        success: false,
        error: 'User account is already active',
      });
      return;
    }

    await prisma.$transaction(async (tx) => {
      // Reactivate user account
      await tx.user.update({
        where: { id: userId },
        data: {
          isActive: true,
          deactivatedAt: null,
          deactivatedBy: null,
          deactivationType: null,
          lastLogin: currentTime,
          updatedAt: currentTime,
        },
      });

      // Log admin action - FIXED: Convert undefined to null
      await tx.securityLog.create({
        data: {
          userId: adminId,
          action: 'ADMIN_REACTIVATED_ACCOUNT',
          ipAddress: req.ip || req.connection.remoteAddress || null,
          userAgent: req.get('User-Agent') || null,
          metadata: {
            targetUserId: userId,
            targetUserEmail: targetUser.email,
            adminEmail: adminUser.email,
            reactivatedAt: currentTime.toISOString(),
          },
        },
      });
    });

    // Send notification email to user
    try {
      await emailService.sendAdminReactivationEmail({
        to: targetUser.email,
        userName:
          targetUser.displayName || targetUser.firstName || targetUser.email,
        adminName: adminUser.displayName || adminUser.email,
        reactivatedAt: currentTime,
      });
      console.log('Admin reactivation notification sent to:', targetUser.email);
    } catch (emailError) {
      console.warn('Admin reactivation notification email failed:', emailError);
    }

    res.json({
      success: true,
      message: 'User account reactivated successfully by admin',
      data: {
        reactivatedUser: {
          id: userId,
          email: targetUser.email,
          isActive: true,
        },
        reactivatedAt: currentTime.toISOString(),
        reactivatedBy: {
          id: adminId,
          email: adminUser.email,
          name: adminUser.displayName,
        },
      },
    });
  } catch (error: any) {
    console.error('Admin reactivate account error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to reactivate user account',
    });
  }
};

// ==================== USER PREFERENCES ====================

/**
 * Get user preferences
 */
export const getUserPreferences = async (
  req: Request,
  res: Response,
): Promise<void> => {
  try {
    if (!req.user) {
      res.status(401).json({
        success: false,
        error: 'Authentication required',
      });
      return;
    }

    const user = await prisma.user.findUnique({
      where: { id: req.user.id },
      select: {
        id: true,
        email: true,
        firstName: true,
        preferences: true,
      },
    });

    if (!user) {
      res.status(404).json({
        success: false,
        error: 'User not found',
      });
      return;
    }

    // Default preferences structure
    const defaultPreferences = {
      notifications: {
        email: true,
        push: true,
        marketing: false,
      },
      privacy: {
        profileVisibility: 'public', // public, private, contacts
        showOnlineStatus: true,
        showLastSeen: true,
      },
      display: {
        theme: 'light', // light, dark, system
        language: 'en',
        timezone: 'UTC',
      },
      emailFrequency: {
        newsletter: 'weekly', // daily, weekly, monthly, never
        updates: 'immediate', // immediate, daily, weekly
        digest: true,
      },
      security: {
        twoFactorEnabled: false,
        loginAlerts: true,
        suspiciousActivityAlerts: true,
      },
    };

    // Parse user preferences
    const currentPrefs = user.preferences
      ? typeof user.preferences === 'string'
        ? JSON.parse(user.preferences)
        : user.preferences
      : {};
    const preferences = { ...defaultPreferences, ...currentPrefs };

    res.json({
      success: true,
      data: {
        preferences,
      },
    });
  } catch (error: any) {
    console.error('Get user preferences error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve user preferences',
    });
  }
};

/**
 * Update user preferences
 */
export const updateUserPreferences = async (
  req: Request,
  res: Response,
): Promise<void> => {
  try {
    if (!req.user) {
      res.status(401).json({
        success: false,
        error: 'Authentication required',
      });
      return;
    }

    const { preferences } = req.body;

    console.log('Updating preferences for user:', req.user.id, preferences);

    // Validate preferences object exists
    if (!preferences || typeof preferences !== 'object') {
      res.status(400).json({
        success: false,
        error: 'Invalid preferences data - must be an object',
      });
      return;
    }

    // Define allowed preference structure
    const allowedStructure = {
      notifications: {
        email: 'boolean',
        push: 'boolean',
        marketing: 'boolean',
      },
      privacy: {
        profileVisibility: 'string', // public, private, contacts
        showOnlineStatus: 'boolean',
        showLastSeen: 'boolean',
      },
      display: {
        theme: 'string', // light, dark, system
        language: 'string',
        timezone: 'string',
      },
      emailFrequency: {
        newsletter: 'string', // daily, weekly, monthly, never
        updates: 'string', // immediate, daily, weekly
        digest: 'boolean',
      },
      security: {
        twoFactorEnabled: 'boolean',
        loginAlerts: 'boolean',
        suspiciousActivityAlerts: 'boolean',
      },
    };

    // Validate and sanitize preferences
    const validPreferences = validateAndMergePreferences(
      preferences,
      allowedStructure,
    );

    // Update user with new preferences
    const updatedUser = await prisma.user.update({
      where: { id: req.user.id },
      data: {
        preferences: validPreferences,
      },
      select: {
        id: true,
        email: true,
        firstName: true,
        preferences: true,
      },
    });

    console.log('Preferences updated successfully for user:', req.user.id);

    // Log preference change - FIXED: Convert undefined to null
    await prisma.securityLog.create({
      data: {
        userId: req.user.id,
        action: 'PREFERENCES_UPDATED',
        ipAddress: req.ip || req.connection.remoteAddress || null,
        userAgent: req.get('User-Agent') || null,
        metadata: {
          preferencesUpdated: Object.keys(preferences),
        },
      },
    });

    res.json({
      success: true,
      message: 'Preferences updated successfully',
      data: {
        user: updatedUser,
      },
    });
  } catch (error: any) {
    console.error('Update user preferences error:', error);

    if (error.message?.includes('Invalid preference')) {
      res.status(400).json({
        success: false,
        error: error.message,
      });
      return;
    }

    res.status(500).json({
      success: false,
      error: 'Failed to update preferences',
    });
  }
};

/**
 * Helper function to validate and merge preferences
 */
function validateAndMergePreferences(
  newPrefs: any,
  allowedStructure: any,
): any {
  const result: any = {};

  for (const [category, rules] of Object.entries(allowedStructure)) {
    if (newPrefs[category] && typeof newPrefs[category] === 'object') {
      result[category] = result[category] || {};

      for (const [key, expectedType] of Object.entries(rules as any)) {
        if (newPrefs[category][key] !== undefined) {
          // Validate type
          if (typeof newPrefs[category][key] === expectedType) {
            result[category][key] = newPrefs[category][key];
          } else {
            console.warn(
              `Invalid type for preference ${category}.${key}: expected ${expectedType}, got ${typeof newPrefs[category][key]}`,
            );
            // Keep default or existing value
          }
        }
      }
    }
  }

  return result;
}

// Export helper functions for testing
export const authUtils = {
  validatePassword,
  isValidEmail,
  hashPassword,
};
