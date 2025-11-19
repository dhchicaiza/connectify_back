import { Router } from 'express';
import { asyncHandler } from '../middleware/errorHandler';
import {
  signup,
  login,
  logout,
  forgotPassword,
  resetPassword,
  googleSignIn,
  githubSignIn,
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
 * @route   POST /api/auth/google
 * @desc    Google Sign-In (verify ID token)
 * @access  Public
 */
router.post('/google', loginRateLimiter, asyncHandler(googleSignIn));

/**
 * @route   POST /api/auth/github
 * @desc    GitHub Sign-In (verify ID token)
 * @access  Public
 */
router.post('/github', loginRateLimiter, asyncHandler(githubSignIn));

/**
 * @route   POST /api/auth/oauth
 * @desc    OAuth login/signup (Facebook and legacy support)
 * @access  Public
 * @deprecated Use /api/auth/google for Google Sign-In or /api/auth/github for GitHub Sign-In
 */
router.post('/oauth', asyncHandler(oauthCallback));

export default router;
