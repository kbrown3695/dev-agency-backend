// src/routes/oauth.routes.ts
import { Router } from 'express';
import { OAuthController } from '../controllers/oauth.controller.js';
import { authenticateToken } from '../middlewares/auth.middleware.js';

const router: Router = Router();
console.log('OAuth routes loaded');
// ==================== PUBLIC ROUTES ====================

/**
 * @route   POST /api/oauth/google/verify
 * @desc    Verify Google OAuth token and login/register user
 * @access  Public
 * @body    { token: string, redirectUri?: string }
 */
router.post('/google/verify', OAuthController.verifyGoogleToken);

/**
 * @route   GET /api/oauth/config
 * @desc    Get OAuth configuration for frontend
 * @access  Public
 * @returns OAuth providers configuration (client IDs, scopes, etc.)
 */
router.get('/config', OAuthController.getOAuthConfig);

// ==================== PROTECTED ROUTES ====================

/**
 * @route   POST /api/oauth/google/unlink
 * @desc    Unlink Google account from user profile
 * @access  Private
 */
router.post(
  '/google/unlink',
  authenticateToken,
  OAuthController.unlinkGoogleAccount,
);

export default router;
