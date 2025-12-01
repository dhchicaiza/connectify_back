import { Response } from 'express';
import { AuthRequest } from '../middleware/auth';
import * as meetingService from '../services/meeting.service';
import { sendSuccess } from '../utils/responseFormatter';
import { BadRequestError, UnauthorizedError } from '../utils/customErrors';
import { logger } from '../utils/logger';
import geminiService from '../services/gemini.service';

/**
 * Create a new meeting - H5
 * POST /api/meetings
 */
export async function createMeeting(req: AuthRequest, res: Response): Promise<Response> {
  try {
    if (!req.user) {
      throw new UnauthorizedError('User not authenticated');
    }

    const { maxParticipants } = req.body;

    // Create meeting
    const meeting = await meetingService.createMeeting({
      createdBy: req.user.userId,
      maxParticipants: maxParticipants ? parseInt(maxParticipants) : undefined,
    });

    return sendSuccess(res, 201, meeting, 'Meeting created successfully');
  } catch (error) {
    logger.error('Create meeting error', error);
    throw error;
  }
}

/**
 * Get meeting by ID
 * GET /api/meetings/:id
 */
export async function getMeeting(req: AuthRequest, res: Response): Promise<Response> {
  try {
    const { id } = req.params;

    if (!id) {
      throw new BadRequestError('Meeting ID is required');
    }

    const meeting = await meetingService.getMeetingById(id);

    return sendSuccess(res, 200, meeting);
  } catch (error) {
    logger.error('Get meeting error', error);
    throw error;
  }
}

/**
 * Get all meetings created by current user
 * GET /api/meetings
 */
export async function getMyMeetings(req: AuthRequest, res: Response): Promise<Response> {
  try {
    if (!req.user) {
      throw new UnauthorizedError('User not authenticated');
    }

    const meetings = await meetingService.getMeetingsByUserId(req.user.userId);

    return sendSuccess(res, 200, meetings);
  } catch (error) {
    logger.error('Get my meetings error', error);
    throw error;
  }
}

/**
 * Join a meeting
 * POST /api/meetings/:id/join
 */
export async function joinMeeting(req: AuthRequest, res: Response): Promise<Response> {
  try {
    if (!req.user) {
      throw new UnauthorizedError('User not authenticated');
    }

    const { id } = req.params;

    if (!id) {
      throw new BadRequestError('Meeting ID is required');
    }

    const meeting = await meetingService.joinMeeting(id, req.user.userId);

    return sendSuccess(res, 200, meeting, 'Joined meeting successfully');
  } catch (error) {
    logger.error('Join meeting error', error);
    throw error;
  }
}

/**
 * Leave a meeting
 * POST /api/meetings/:id/leave
 */
export async function leaveMeeting(req: AuthRequest, res: Response): Promise<Response> {
  try {
    if (!req.user) {
      throw new UnauthorizedError('User not authenticated');
    }

    const { id } = req.params;

    if (!id) {
      throw new BadRequestError('Meeting ID is required');
    }

    await meetingService.leaveMeeting(id, req.user.userId);

    return sendSuccess(res, 200, null, 'Left meeting successfully');
  } catch (error) {
    logger.error('Leave meeting error', error);
    throw error;
  }
}

/**
 * End a meeting
 * POST /api/meetings/:id/end
 */
export async function endMeeting(req: AuthRequest, res: Response): Promise<Response> {
  try {
    if (!req.user) {
      throw new UnauthorizedError('User not authenticated');
    }

    const { id } = req.params;

    if (!id) {
      throw new BadRequestError('Meeting ID is required');
    }

    await meetingService.endMeeting(id, req.user.userId);

    return sendSuccess(res, 200, null, 'Meeting ended successfully');
  } catch (error) {
    logger.error('End meeting error', error);
    throw error;
  }
}

/**
 * Generate AI summary for a meeting
 * POST /api/meetings/:id/summary
 */
export async function generateMeetingSummary(req: AuthRequest, res: Response): Promise<Response> {
  try {
    if (!req.user) {
      throw new UnauthorizedError('User not authenticated');
    }

    const { id } = req.params;
    const { messages } = req.body;

    if (!id) {
      throw new BadRequestError('Meeting ID is required');
    }

    if (!messages || !Array.isArray(messages) || messages.length === 0) {
      throw new BadRequestError('Chat messages are required to generate summary');
    }

    logger.info(`Generating summary for meeting ${id}`);

    // Generate summary using Gemini AI
    const summary = await geminiService.generateMeetingSummary(messages, id);

    // Save summary to Firestore
    await meetingService.saveMeetingSummary(id, summary);

    return sendSuccess(res, 200, summary, 'Summary generated successfully');
  } catch (error) {
    logger.error('Generate summary error', error);
    throw error;
  }
}
