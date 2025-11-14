import { Router } from 'express';
import { asyncHandler } from '../middleware/errorHandler';
import {
  signup,
  login,
  logout,
  forgotPassword,
  resetPassword,
  oauthCallback,
} from '../controllers/auth.controller';
import {
  loginRateLimiter,
  passwordResetRateLimiter,
  signupRateLimiter,
} from '../middleware/rateLimiter';
import { authenticate } from '../middleware/auth';

const router = Router();

/**
 * @route   POST /api/auth/signup
 * @desc    Register a new user
 * @access  Public
 */
router.post('/signup', signupRateLimiter, asyncHandler(signup));

/**
 * @route   POST /api/auth/login
 * @desc    Login user
 * @access  Public
 */
router.post('/login', loginRateLimiter, asyncHandler(login));

/**
 * @route   POST /api/auth/logout
 * @desc    Logout user
 * @access  Protected
 */
router.post('/logout', authenticate, asyncHandler(logout));

/**
 * @route   POST /api/auth/forgot-password
 * @desc    Request password reset
 * @access  Public
 */
router.post('/forgot-password', passwordResetRateLimiter, asyncHandler(forgotPassword));

/**
 * @route   POST /api/auth/reset-password
 * @desc    Reset password with token
 * @access  Public
 */
router.post('/reset-password', asyncHandler(resetPassword));

/**
 * @route   POST /api/auth/oauth
 * @desc    OAuth login/signup (Google/Facebook)
 * @access  Public
 */
router.post('/oauth', asyncHandler(oauthCallback));

export default router;
