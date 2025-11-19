/**
 * Meeting participant interface
 */
export interface Participant {
  userId: string;
  joinedAt: string; // ISO-8601 format
  active: boolean;
}

/**
 * Meeting model interface for Firestore
 */
export interface Meeting {
  id: string;
  createdBy: string; // User ID
  createdAt: string; // ISO-8601 format
  updatedAt: string; // ISO-8601 format
  status: 'active' | 'ended';
  participants: Participant[];
  maxParticipants: number; // 2-10
}

/**
 * Create meeting data
 */
export interface CreateMeetingData {
  createdBy: string;
  maxParticipants?: number;
}

/**
 * Meeting response (for API)
 */
export interface MeetingResponse {
  id: string;
  createdBy: string;
  createdAt: string;
  status: 'active' | 'ended';
  participants: Participant[];
  maxParticipants: number;
  participantCount: number;
  canJoin: boolean;
}

/**
 * Convert Meeting to MeetingResponse
 * @param meeting - Meeting object
 * @returns MeetingResponse object
 */
export function toMeetingResponse(meeting: Meeting): MeetingResponse {
  const activeParticipants = meeting.participants.filter((p) => p.active);

  return {
    id: meeting.id,
    createdBy: meeting.createdBy,
    createdAt: meeting.createdAt,
    status: meeting.status,
    participants: meeting.participants,
    maxParticipants: meeting.maxParticipants,
    participantCount: activeParticipants.length,
    canJoin: meeting.status === 'active' && activeParticipants.length < meeting.maxParticipants,
  };
}
