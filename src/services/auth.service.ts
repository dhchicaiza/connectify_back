import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import { getFirestore, COLLECTIONS } from '../config/firebase';
import { User, CreateUserData, toUserResponse, UserResponse } from '../models/User';
import { PasswordResetToken } from '../models/PasswordResetToken';
import { ConflictError, UnauthorizedError, NotFoundError, BadRequestError } from '../utils/customErrors';
import { logger } from '../utils/logger';
import { sendPasswordResetEmail } from '../config/email';

const SALT_ROUNDS = 10;
const PASSWORD_RESET_TOKEN_EXPIRY_HOURS = 1;

/**
 * Hash a password using bcrypt
 * @param password - Plain text password
 * @returns Hashed password
 */
async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, SALT_ROUNDS);
}

/**
 * Compare password with hash
 * @param password - Plain text password
 * @param hash - Hashed password
 * @returns True if passwords match
 */
async function comparePassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

/**
 * Check if email already exists in database
 * @param email - Email to check
 * @returns True if email exists
 */
export async function emailExists(email: string): Promise<boolean> {
  const db = getFirestore();
  const usersRef = db.collection(COLLECTIONS.USERS);

  const snapshot = await usersRef.where('email', '==', email).limit(1).get();

  return !snapshot.empty;
}

/**
 * Create a new user (Sign-up)
 * @param userData - User creation data
 * @returns Created user response
 */
export async function createUser(userData: CreateUserData): Promise<UserResponse> {
  try {
    const db = getFirestore();

    // Check if email already exists
    if (await emailExists(userData.email)) {
      throw new ConflictError('Email already registered');
    }

    // Hash the password
    const hashedPassword = await hashPassword(userData.password);

    // Create user object
    const userId = uuidv4();
    const now = new Date().toISOString();

    const newUser: User = {
      id: userId,
      firstName: userData.firstName,
      lastName: userData.lastName,
      age: userData.age,
      email: userData.email,
      password: hashedPassword,
      provider: userData.provider || 'email',
      providerId: userData.providerId,
      createdAt: now,
      updatedAt: now,
      isActive: true,
      failedLoginAttempts: 0,
    };

    // Save to Firestore
    await db.collection(COLLECTIONS.USERS).doc(userId).set(newUser);

    logger.info(`User created successfully: ${userId}`);

    return toUserResponse(newUser);
  } catch (error) {
    logger.error('Error creating user', error);
    throw error;
  }
}

/**
 * Login user with email and password
 * @param email - User email
 * @param password - User password
 * @returns User response
 */
export async function loginUser(email: string, password: string): Promise<UserResponse> {
  try {
    const db = getFirestore();
    const usersRef = db.collection(COLLECTIONS.USERS);

    // Find user by email
    const snapshot = await usersRef.where('email', '==', email).limit(1).get();

    if (snapshot.empty) {
      throw new UnauthorizedError('Invalid email or password');
    }

    const userDoc = snapshot.docs[0];
    if (!userDoc) {
      throw new UnauthorizedError('Invalid email or password');
    }

    const user = userDoc.data() as User;

    // Check if account is locked
    if (user.lockUntil && new Date(user.lockUntil) > new Date()) {
      throw new UnauthorizedError('Account temporarily locked due to multiple failed login attempts');
    }

    // Verify password
    const isPasswordValid = await comparePassword(password, user.password);

    if (!isPasswordValid) {
      // Increment failed login attempts
      const failedAttempts = (user.failedLoginAttempts || 0) + 1;
      const updates: Partial<User> = {
        failedLoginAttempts: failedAttempts,
        updatedAt: new Date().toISOString(),
      };

      // Lock account after 5 failed attempts
      if (failedAttempts >= 5) {
        const lockUntil = new Date();
        lockUntil.setMinutes(lockUntil.getMinutes() + 10); // Lock for 10 minutes
        updates.lockUntil = lockUntil.toISOString();
        logger.warn(`Account locked for user: ${user.id}`);
      }

      await userDoc.ref.update(updates);

      throw new UnauthorizedError('Invalid email or password');
    }

    // Reset failed login attempts on successful login
    if (user.failedLoginAttempts && user.failedLoginAttempts > 0) {
      await userDoc.ref.update({
        failedLoginAttempts: 0,
        lockUntil: null,
        updatedAt: new Date().toISOString(),
      });
    }

    logger.info(`User logged in successfully: ${user.id}`);

    return toUserResponse(user);
  } catch (error) {
    logger.error('Error logging in user', error);
    throw error;
  }
}

/**
 * Get user by ID
 * @param userId - User ID
 * @returns User response
 */
export async function getUserById(userId: string): Promise<UserResponse> {
  try {
    const db = getFirestore();
    const userDoc = await db.collection(COLLECTIONS.USERS).doc(userId).get();

    if (!userDoc.exists) {
      throw new NotFoundError('User not found');
    }

    const user = userDoc.data() as User;
    return toUserResponse(user);
  } catch (error) {
    logger.error('Error getting user by ID', error);
    throw error;
  }
}

/**
 * Get user by email
 * @param email - User email
 * @returns User or null
 */
export async function getUserByEmail(email: string): Promise<User | null> {
  try {
    const db = getFirestore();
    const usersRef = db.collection(COLLECTIONS.USERS);
    const snapshot = await usersRef.where('email', '==', email).limit(1).get();

    if (snapshot.empty) {
      return null;
    }

    return snapshot.docs[0]?.data() as User;
  } catch (error) {
    logger.error('Error getting user by email', error);
    throw error;
  }
}

/**
 * Request password reset
 * @param email - User email
 */
export async function requestPasswordReset(email: string): Promise<void> {
  try {
    const user = await getUserByEmail(email);

    // Always return success to prevent email enumeration
    if (!user) {
      logger.info(`Password reset requested for non-existent email: ${email}`);
      return;
    }

    const db = getFirestore();

    // Generate reset token
    const resetToken = uuidv4();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + PASSWORD_RESET_TOKEN_EXPIRY_HOURS * 60 * 60 * 1000);

    const passwordResetToken: PasswordResetToken = {
      id: resetToken,
      userId: user.id,
      email: user.email,
      createdAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
      used: false,
    };

    // Save token to Firestore
    await db.collection(COLLECTIONS.PASSWORD_RESET_TOKENS).doc(resetToken).set(passwordResetToken);

    // Send reset email
    await sendPasswordResetEmail(email, resetToken);

    logger.info(`Password reset email sent to: ${email}`);
  } catch (error) {
    logger.error('Error requesting password reset', error);
    throw error;
  }
}

/**
 * Reset password using token
 * @param token - Reset token
 * @param newPassword - New password
 */
export async function resetPassword(token: string, newPassword: string): Promise<void> {
  try {
    const db = getFirestore();

    // Get reset token
    const tokenDoc = await db.collection(COLLECTIONS.PASSWORD_RESET_TOKENS).doc(token).get();

    if (!tokenDoc.exists) {
      throw new BadRequestError('Invalid or expired reset link');
    }

    const resetToken = tokenDoc.data() as PasswordResetToken;

    // Check if token is used
    if (resetToken.used) {
      throw new BadRequestError('Reset link has already been used');
    }

    // Check if token is expired
    if (new Date(resetToken.expiresAt) < new Date()) {
      throw new BadRequestError('Reset link has expired');
    }

    // Hash new password
    const hashedPassword = await hashPassword(newPassword);

    // Update user password
    await db.collection(COLLECTIONS.USERS).doc(resetToken.userId).update({
      password: hashedPassword,
      updatedAt: new Date().toISOString(),
      failedLoginAttempts: 0,
      lockUntil: null,
    });

    // Mark token as used
    await tokenDoc.ref.update({ used: true });

    logger.info(`Password reset successfully for user: ${resetToken.userId}`);
  } catch (error) {
    logger.error('Error resetting password', error);
    throw error;
  }
}

/**
 * Update user profile
 * @param userId - User ID
 * @param updateData - Fields to update
 * @returns Updated user response
 */
export async function updateUserProfile(
  userId: string,
  updateData: {
    firstName?: string;
    lastName?: string;
    age?: number;
    email?: string;
  }
): Promise<UserResponse> {
  try {
    const db = getFirestore();
    const userRef = db.collection(COLLECTIONS.USERS).doc(userId);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      throw new NotFoundError('User not found');
    }

    // If email is being updated, check if it's already in use
    if (updateData.email && updateData.email !== (userDoc.data() as User).email) {
      if (await emailExists(updateData.email)) {
        throw new ConflictError('Email already in use');
      }
    }

    // Update user
    const updates = {
      ...updateData,
      updatedAt: new Date().toISOString(),
    };

    await userRef.update(updates);

    // Get updated user
    const updatedUserDoc = await userRef.get();
    const updatedUser = updatedUserDoc.data() as User;

    logger.info(`User profile updated: ${userId}`);

    return toUserResponse(updatedUser);
  } catch (error) {
    logger.error('Error updating user profile', error);
    throw error;
  }
}
