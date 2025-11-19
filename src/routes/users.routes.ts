import { Router } from 'express';
import { asyncHandler } from '../middleware/errorHandler';
import { getProfile, updateProfile, deleteAccount } from '../controllers/users.controller';
import { authenticate } from '../middleware/auth';

const router = Router();

// All user routes require authentication
router.use(authenticate);

/**
 * @route   GET /api/users/me
 * @desc    Get current user profile
 * @access  Protected
 */
router.get('/me', asyncHandler(getProfile));

/**
 * @route   PUT /api/users/me
 * @desc    Update current user profile
 * @access  Protected
 */
router.put('/me', asyncHandler(updateProfile));

/**
 * @route   DELETE /api/users/me
 * @desc    Delete current user account
 * @access  Protected
 */
router.delete('/me', asyncHandler(deleteAccount));

export default router;
