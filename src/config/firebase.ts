import admin from 'firebase-admin';
import { logger } from '../utils/logger';

/**
 * Initialize Firebase Admin SDK
 * Uses environment variables for configuration
 */
export function initializeFirebase(): void {
  try {
    // Check if Firebase is already initialized
    if (admin.apps.length > 0) {
      logger.info('Firebase Admin SDK already initialized');
      return;
    }

    // Validate required environment variables
    const requiredEnvVars = [
      'FIREBASE_PROJECT_ID',
      'FIREBASE_PRIVATE_KEY',
      'FIREBASE_CLIENT_EMAIL',
    ];

    for (const envVar of requiredEnvVars) {
      if (!process.env[envVar]) {
        throw new Error(`Missing required environment variable: ${envVar}`);
      }
    }

    // Initialize Firebase Admin with service account
    admin.initializeApp({
      credential: admin.credential.cert({
        projectId: process.env.FIREBASE_PROJECT_ID,
        privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
        clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      }),
    });

    logger.info('Firebase Admin SDK initialized successfully');
  } catch (error) {
    logger.error('Failed to initialize Firebase Admin SDK', error);
    throw error;
  }
}

/**
 * Get Firestore database instance
 * @returns Firestore database instance
 */
export function getFirestore(): admin.firestore.Firestore {
  return admin.firestore();
}

/**
 * Get Firebase Auth instance
 * @returns Firebase Auth instance
 */
export function getAuth(): admin.auth.Auth {
  return admin.auth();
}

/**
 * Collection names constants
 */
export const COLLECTIONS = {
  USERS: 'users',
  MEETINGS: 'meetings',
  CHAT: 'chat',
  SUMMARIES: 'summaries',
  PASSWORD_RESET_TOKENS: 'passwordResetTokens',
} as const;
