import { v4 as uuidv4 } from 'uuid';
import { getFirestore, COLLECTIONS } from '../config/firebase';
import { Meeting, CreateMeetingData, toMeetingResponse, MeetingResponse } from '../models/Meeting';
import { NotFoundError, BadRequestError, ConflictError } from '../utils/customErrors';
import { logger } from '../utils/logger';

const DEFAULT_MAX_PARTICIPANTS = 10;
const MIN_PARTICIPANTS = 2;
const MAX_PARTICIPANTS = 10;

/**
 * Create a new meeting - H5
 * @param meetingData - Meeting creation data
 * @returns Created meeting response
 */
export async function createMeeting(meetingData: CreateMeetingData): Promise<MeetingResponse> {
  try {
    const db = getFirestore();

    // Validate maxParticipants
    const maxParticipants = meetingData.maxParticipants || DEFAULT_MAX_PARTICIPANTS;

    if (maxParticipants < MIN_PARTICIPANTS || maxParticipants > MAX_PARTICIPANTS) {
      throw new BadRequestError(`Maximum participants must be between ${MIN_PARTICIPANTS} and ${MAX_PARTICIPANTS}`);
    }

    // Generate meeting ID
    const meetingId = uuidv4();
    const now = new Date().toISOString();

    const newMeeting: Meeting = {
      id: meetingId,
      createdBy: meetingData.createdBy,
      createdAt: now,
      updatedAt: now,
      status: 'active',
      participants: [],
      maxParticipants,
    };

    // Save to Firestore
    await db.collection(COLLECTIONS.MEETINGS).doc(meetingId).set(newMeeting);

    logger.info(`Meeting created successfully: ${meetingId} by user: ${meetingData.createdBy}`);

    return toMeetingResponse(newMeeting);
  } catch (error) {
    logger.error('Error creating meeting', error);
    throw error;
  }
}

/**
 * Get meeting by ID
 * @param meetingId - Meeting ID
 * @returns Meeting response
 */
export async function getMeetingById(meetingId: string): Promise<MeetingResponse> {
  try {
    const db = getFirestore();
    const meetingDoc = await db.collection(COLLECTIONS.MEETINGS).doc(meetingId).get();

    if (!meetingDoc.exists) {
      throw new NotFoundError('Meeting not found');
    }

    const meeting = meetingDoc.data() as Meeting;
    return toMeetingResponse(meeting);
  } catch (error) {
    logger.error('Error getting meeting by ID', error);
    throw error;
  }
}

/**
 * Get meetings created by a user
 * @param userId - User ID
 * @returns List of meeting responses
 */
export async function getMeetingsByUserId(userId: string): Promise<MeetingResponse[]> {
  try {
    const db = getFirestore();
    const meetingsRef = db.collection(COLLECTIONS.MEETINGS);

    const snapshot = await meetingsRef
      .where('createdBy', '==', userId)
      .orderBy('createdAt', 'desc')
      .get();

    const meetings = snapshot.docs.map((doc) => {
      const meeting = doc.data() as Meeting;
      return toMeetingResponse(meeting);
    });

    return meetings;
  } catch (error) {
    logger.error('Error getting meetings by user ID', error);
    throw error;
  }
}

/**
 * Join a meeting
 * @param meetingId - Meeting ID
 * @param userId - User ID
 * @returns Updated meeting response
 */
export async function joinMeeting(meetingId: string, userId: string): Promise<MeetingResponse> {
  try {
    const db = getFirestore();
    const meetingRef = db.collection(COLLECTIONS.MEETINGS).doc(meetingId);
    const meetingDoc = await meetingRef.get();

    if (!meetingDoc.exists) {
      throw new NotFoundError('Meeting not found');
    }

    const meeting = meetingDoc.data() as Meeting;

    // Check if meeting is active
    if (meeting.status !== 'active') {
      throw new BadRequestError('This meeting has ended');
    }

    // Check if user is already in the meeting
    const existingParticipant = meeting.participants.find((p) => p.userId === userId);

    if (existingParticipant) {
      // Reactivate participant if they were inactive
      if (!existingParticipant.active) {
        const updatedParticipants = meeting.participants.map((p) =>
          p.userId === userId ? { ...p, active: true } : p
        );

        await meetingRef.update({
          participants: updatedParticipants,
          updatedAt: new Date().toISOString(),
        });

        logger.info(`User ${userId} rejoined meeting: ${meetingId}`);
      }
    } else {
      // Check if meeting is full
      const activeParticipants = meeting.participants.filter((p) => p.active);

      if (activeParticipants.length >= meeting.maxParticipants) {
        throw new BadRequestError('Meeting is full');
      }

      // Add new participant
      const newParticipant = {
        userId,
        joinedAt: new Date().toISOString(),
        active: true,
      };

      await meetingRef.update({
        participants: [...meeting.participants, newParticipant],
        updatedAt: new Date().toISOString(),
      });

      logger.info(`User ${userId} joined meeting: ${meetingId}`);
    }

    // Get updated meeting
    const updatedMeetingDoc = await meetingRef.get();
    const updatedMeeting = updatedMeetingDoc.data() as Meeting;

    return toMeetingResponse(updatedMeeting);
  } catch (error) {
    logger.error('Error joining meeting', error);
    throw error;
  }
}

/**
 * Leave a meeting
 * @param meetingId - Meeting ID
 * @param userId - User ID
 */
export async function leaveMeeting(meetingId: string, userId: string): Promise<void> {
  try {
    const db = getFirestore();
    const meetingRef = db.collection(COLLECTIONS.MEETINGS).doc(meetingId);
    const meetingDoc = await meetingRef.get();

    if (!meetingDoc.exists) {
      throw new NotFoundError('Meeting not found');
    }

    const meeting = meetingDoc.data() as Meeting;

    // Mark participant as inactive
    const updatedParticipants = meeting.participants.map((p) =>
      p.userId === userId ? { ...p, active: false } : p
    );

    await meetingRef.update({
      participants: updatedParticipants,
      updatedAt: new Date().toISOString(),
    });

    logger.info(`User ${userId} left meeting: ${meetingId}`);
  } catch (error) {
    logger.error('Error leaving meeting', error);
    throw error;
  }
}

/**
 * End a meeting
 * @param meetingId - Meeting ID
 * @param userId - User ID (must be creator)
 */
export async function endMeeting(meetingId: string, userId: string): Promise<void> {
  try {
    const db = getFirestore();
    const meetingRef = db.collection(COLLECTIONS.MEETINGS).doc(meetingId);
    const meetingDoc = await meetingRef.get();

    if (!meetingDoc.exists) {
      throw new NotFoundError('Meeting not found');
    }

    const meeting = meetingDoc.data() as Meeting;

    // Check if user is the creator
    if (meeting.createdBy !== userId) {
      throw new BadRequestError('Only the meeting creator can end the meeting');
    }

    // End the meeting
    await meetingRef.update({
      status: 'ended',
      updatedAt: new Date().toISOString(),
    });

    logger.info(`Meeting ended: ${meetingId} by user: ${userId}`);
  } catch (error) {
    logger.error('Error ending meeting', error);
    throw error;
  }
}

/**
 * Delete a meeting
 * @param meetingId - Meeting ID
 * @param userId - User ID (must be creator)
 */
export async function deleteMeeting(meetingId: string, userId: string): Promise<void> {
  try {
    const db = getFirestore();
    const meetingRef = db.collection(COLLECTIONS.MEETINGS).doc(meetingId);
    const meetingDoc = await meetingRef.get();

    if (!meetingDoc.exists) {
      throw new NotFoundError('Meeting not found');
    }

    const meeting = meetingDoc.data() as Meeting;

    // Check if user is the creator
    if (meeting.createdBy !== userId) {
      throw new BadRequestError('Only the meeting creator can delete the meeting');
    }

    // All participants must have leave the meeting
    meeting.participants.map((participant) => {
      // If there's at least one participant on the meeting throw error
      if (participant.active === true) throw new ConflictError('All participants must leave the meeting');
    })

    // Delete the meeting
    await meetingRef.delete();

    logger.info(`Meeting deleted: ${meetingId} by user: ${userId}`);
  } catch (error) {
    logger.error('Error deleting meeting', error);
    throw error;
  }
}