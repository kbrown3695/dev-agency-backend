// src/routes/auth.routes.ts
import { Router } from 'express';
import {
  register,
  login,
  logout,
  getCurrentUser,
  verifyEmail,
  resendVerificationEmail,
  requestPasswordReset,
  resetPassword,
  changePassword,
  updateProfile,
  refreshToken,
  deactivateAccount,
  checkAccountStatus,
  checkUserStatus,
  requestReactivation,
  completeReactivation,
  adminDeactivateAccount,
  adminReactivateAccount,
  getUserPreferences,
  updateUserPreferences,
} from '../controllers/auth.controller.js';
import {
  authenticateToken,
  requireAdmin,
} from '../middlewares/auth.middleware.js';

const router: Router = Router();

console.log('Auth routes loaded');
// ==================== PUBLIC ROUTES ====================

/**
 * @route   POST /api/auth/register
 * @desc    Register a new user
 * @access  Public
 */
router.post('/register', register);

/**
 * @route   POST /api/auth/login
 * @desc    Login user
 * @access  Public
 */
router.post('/login', login);

/**
 * @route   GET /api/auth/verify-email
 * @desc    Verify user email with token
 * @access  Public
 * @query   token - Verification token
 */
router.get('/verify-email', verifyEmail);

/**
 * @route   POST /api/auth/resend-verification
 * @desc    Resend verification email
 * @access  Public
 */
router.post('/resend-verification', resendVerificationEmail);

/**
 * @route   POST /api/auth/request-password-reset
 * @desc    Request password reset email
 * @access  Public
 */
router.post('/request-password-reset', requestPasswordReset);

/**
 * @route   POST /api/auth/reset-password
 * @desc    Reset password with token
 * @access  Public
 */
router.post('/reset-password', resetPassword);

/**
 * @route   POST /api/auth/check-account-status
 * @desc    Check if account exists and is active/deactivated
 * @access  Public
 */
router.post('/check-account-status', checkAccountStatus);

/**
 * @route   POST /api/auth/request-reactivation
 * @desc    Request account reactivation for deactivated account
 * @access  Public
 */
router.post('/request-reactivation', requestReactivation);

/**
 * @route   POST /api/auth/complete-reactivation
 * @desc    Complete account reactivation with token and new password
 * @access  Public
 */
router.post('/complete-reactivation', completeReactivation);

// ==================== PROTECTED ROUTES ====================

/**
 * @route   POST /api/auth/logout
 * @desc    Logout user and invalidate session
 * @access  Private
 */
router.post('/logout', authenticateToken, logout);

/**
 * @route   GET /api/auth/me
 * @desc    Get current authenticated user
 * @access  Private
 */
router.get('/me', authenticateToken, getCurrentUser);

/**
 * @route   GET /api/auth/status
 * @desc    Check authenticated user status and token validity
 * @access  Private
 */
router.get('/status', authenticateToken, checkUserStatus);

/**
 * @route   POST /api/auth/change-password
 * @desc    Change user password
 * @access  Private
 */
router.post('/change-password', authenticateToken, changePassword);

/**
 * @route   PUT /api/auth/profile
 * @desc    Update user profile
 * @access  Private
 */
router.put('/profile', authenticateToken, updateProfile);

/**
 * @route   POST /api/auth/refresh-token
 * @desc    Refresh JWT token
 * @access  Private
 */
router.post('/refresh-token', authenticateToken, refreshToken);

/**
 * @route   POST /api/auth/deactivate-account
 * @desc    User-initiated account deactivation
 * @access  Private
 */
router.post('/deactivate-account', authenticateToken, deactivateAccount);

/**
 * @route   GET /api/auth/preferences
 * @desc    Get user preferences
 * @access  Private
 */
router.get('/preferences', authenticateToken, getUserPreferences);

/**
 * @route   PUT /api/auth/preferences
 * @desc    Update user preferences
 * @access  Private
 */
router.put('/preferences', authenticateToken, updateUserPreferences);

// ==================== ADMIN ROUTES ====================

/**
 * @route   POST /api/auth/admin/deactivate/:userId
 * @desc    Admin deactivate user account
 * @access  Private (Admin/Moderator)
 */
router.post(
  '/admin/deactivate/:userId',
  authenticateToken,
  requireAdmin,
  adminDeactivateAccount,
);

/**
 * @route   POST /api/auth/admin/reactivate/:userId
 * @desc    Admin reactivate user account
 * @access  Private (Admin/Moderator)
 */
router.post(
  '/admin/reactivate/:userId',
  authenticateToken,
  requireAdmin,
  adminReactivateAccount,
);

export default router;
