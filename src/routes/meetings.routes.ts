import { Router } from 'express';
import { asyncHandler } from '../middleware/errorHandler';
import {
  createMeeting,
  getMeeting,
  getMyMeetings,
  joinMeeting,
  leaveMeeting,
  endMeeting,
} from '../controllers/meetings.controller';
import { authenticate } from '../middleware/auth';

const router = Router();

// All meeting routes require authentication
router.use(authenticate);

/**
 * @route   POST /api/meetings
 * @desc    Create a new meeting
 * @access  Protected
 */
router.post('/', asyncHandler(createMeeting));

/**
 * @route   GET /api/meetings
 * @desc    Get all meetings created by current user
 * @access  Protected
 */
router.get('/', asyncHandler(getMyMeetings));

/**
 * @route   GET /api/meetings/:id
 * @desc    Get meeting by ID
 * @access  Protected
 */
router.get('/:id', asyncHandler(getMeeting));

/**
 * @route   POST /api/meetings/:id/join
 * @desc    Join a meeting
 * @access  Protected
 */
router.post('/:id/join', asyncHandler(joinMeeting));

/**
 * @route   POST /api/meetings/:id/leave
 * @desc    Leave a meeting
 * @access  Protected
 */
router.post('/:id/leave', asyncHandler(leaveMeeting));

/**
 * @route   POST /api/meetings/:id/end
 * @desc    End a meeting (creator only)
 * @access  Protected
 */
router.post('/:id/end', asyncHandler(endMeeting));

export default router;
