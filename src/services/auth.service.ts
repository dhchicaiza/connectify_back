import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import { getFirestore, getAuth, COLLECTIONS } from '../config/firebase';
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
      providerId: userData.providerId || '',
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
 * Verifies a user's current password
 *
 * @async
 * @function verifyUserPassword
 * @param {string} userId - User ID
 * @param {string} password - Plain text password to verify
 * @returns {Promise<boolean>} True if password matches, false otherwise
 *
 * @throws {NotFoundError} If user is not found
 * @throws {Error} If database operation fails
 *
 * @description
 * This function retrieves the user's hashed password from the database
 * and compares it with the provided plain text password using bcrypt.
 * Used for verifying current password before allowing password changes.
 *
 * @example
 * const isValid = await verifyUserPassword('user-uuid', 'MyPassword123!');
 * if (isValid) {
 *   console.log('Password is correct');
 * }
 */
export async function verifyUserPassword(userId: string, password: string): Promise<boolean> {
  try {
    const db = getFirestore();
    const userDoc = await db.collection(COLLECTIONS.USERS).doc(userId).get();

    if (!userDoc.exists) {
      throw new NotFoundError('User not found');
    }

    const user = userDoc.data() as User;

    // Users authenticated via OAuth don't have passwords
    if (!user.password || user.provider !== 'email') {
      return false;
    }

    // Compare provided password with stored hash
    return await comparePassword(password, user.password);
  } catch (error) {
    logger.error('Error verifying user password', error);
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
 * Updates user profile information including optional password change
 *
 * @async
 * @function updateUserProfile
 * @param {string} userId - User ID
 * @param {Object} updateData - Fields to update
 * @param {string} [updateData.firstName] - User's first name
 * @param {string} [updateData.lastName] - User's last name
 * @param {number} [updateData.age] - User's age
 * @param {string} [updateData.email] - User's email address
 * @param {string} [updateData.password] - New password (will be hashed before storing)
 * @returns {Promise<UserResponse>} Updated user response
 *
 * @throws {NotFoundError} If user is not found
 * @throws {ConflictError} If email is already in use by another user
 * @throws {Error} If database operation fails
 *
 * @description
 * This function allows updating user profile fields. If a password is provided,
 * it will be hashed using bcrypt before storing. Email uniqueness is verified
 * before updating. The updatedAt timestamp is automatically set.
 *
 * @example
 * const updated = await updateUserProfile('user-uuid', {
 *   firstName: 'John',
 *   email: 'newemail@example.com',
 *   password: 'NewSecurePass123!'
 * });
 */
export async function updateUserProfile(
  userId: string,
  updateData: {
    firstName?: string;
    lastName?: string;
    age?: number;
    email?: string;
    password?: string;
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

    // Prepare updates object
    const updates: any = {
      ...updateData,
      updatedAt: new Date().toISOString(),
    };

    // Hash password if provided
    if (updateData.password) {
      updates.password = await hashPassword(updateData.password);
      logger.info(`Password updated for user: ${userId}`);
    }

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

/**
 * Verifies a Google ID Token using Firebase Admin SDK and extracts user information.
 *
 * @async
 * @function verifyGoogleToken
 * @param {string} idToken - Google ID token obtained from Firebase Authentication client SDK
 * @returns {Promise<Object>} Decoded token data containing user information
 * @returns {string} return.uid - Firebase user unique identifier
 * @returns {string} return.email - User's email address
 * @returns {string} return.name - User's display name from Google account
 * @returns {string} [return.picture] - URL to user's profile picture (optional)
 * @returns {boolean} return.email_verified - Whether the email has been verified by Google
 *
 * @throws {BadRequestError} If email is not found in token or email is not verified
 * @throws {UnauthorizedError} If token verification fails or token is invalid
 *
 * @description
 * This function uses Firebase Admin SDK to verify the authenticity of the Google ID token.
 * It ensures that:
 * - The token is valid and signed by Google
 * - The token has not expired
 * - The email address is present and verified
 *
 * @example
 * const tokenData = await verifyGoogleToken('eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...');
 * console.log(tokenData.email); // 'user@gmail.com'
 * console.log(tokenData.uid); // 'firebase-user-id'
 */
export async function verifyGoogleToken(idToken: string): Promise<{
  uid: string;
  email: string;
  name: string;
  picture?: string;
  email_verified: boolean;
}> {
  try {
    const auth = getAuth();

    // Verify the ID token using Firebase Admin SDK
    const decodedToken = await auth.verifyIdToken(idToken);

    // Extract user information
    const { uid, email, name, picture, email_verified } = decodedToken;

    if (!email) {
      throw new BadRequestError('Email not found in token');
    }

    if (!email_verified) {
      throw new BadRequestError('Email not verified');
    }

    logger.info(`Google token verified for user: ${uid}`);

    return {
      uid,
      email,
      name: name || '',
      picture,
      email_verified,
    };
  } catch (error) {
    logger.error('Error verifying Google token', error);
    throw new UnauthorizedError('Invalid Google authentication token');
  }
}

/**
 * Authenticates a user with Google OAuth or creates a new account if the user doesn't exist.
 *
 * @async
 * @function loginWithGoogle
 * @param {string} idToken - Google ID token obtained from Firebase Authentication client SDK
 * @returns {Promise<Object>} Authentication result containing user data and creation status
 * @returns {UserResponse} return.user - User information without sensitive data (password excluded)
 * @returns {boolean} return.isNewUser - Indicates whether a new user account was created (true) or existing user logged in (false)
 *
 * @throws {UnauthorizedError} If the Google token is invalid or verification fails
 * @throws {Error} If database operations fail
 *
 * @description
 * This function implements the complete Google Sign-In flow:
 *
 * **For existing users:**
 * 1. Verifies the Google ID token using Firebase Admin SDK
 * 2. Searches for user by email in Firestore
 * 3. Updates the last login timestamp
 * 4. Returns user data with isNewUser: false
 *
 * **For new users:**
 * 1. Verifies the Google ID token
 * 2. Extracts first and last name from Google display name
 * 3. Creates a new user document in Firestore with:
 *    - Unique UUID
 *    - Google provider information
 *    - Default age (18)
 *    - No password (OAuth users don't need passwords)
 * 4. Returns user data with isNewUser: true
 *
 * **Security features:**
 * - Token verification ensures authenticity
 * - Only verified Google emails are accepted
 * - Provider ID is stored for future reference
 * - No password is stored for OAuth users
 *
 * @example
 * const result = await loginWithGoogle('eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...');
 *
 * if (result.isNewUser) {
 *   console.log('New user created:', result.user.email);
 * } else {
 *   console.log('Existing user logged in:', result.user.email);
 * }
 *
 * // Generate JWT for the user
 * const token = generateToken({ userId: result.user.id, email: result.user.email });
 */
export async function loginWithGoogle(idToken: string): Promise<{
  user: UserResponse;
  isNewUser: boolean;
}> {
  try {
    // Verify the Google token
    const tokenData = await verifyGoogleToken(idToken);

    const db = getFirestore();

    // Check if user exists by email
    let user = await getUserByEmail(tokenData.email);

    if (user) {
      // User exists - update their info if needed
      logger.info(`Existing user logging in with Google: ${user.id}`);

      // Update last login time
      await db.collection(COLLECTIONS.USERS).doc(user.id).update({
        updatedAt: new Date().toISOString(),
      });

      return {
        user: toUserResponse(user),
        isNewUser: false,
      };
    } else {
      // Create new user

      // Extract first and last name from display name
      const nameParts = tokenData.name.trim().split(' ');
      const firstName = nameParts[0] || 'User';
      const lastName = nameParts.slice(1).join(' ') || 'Google';

      const userId = uuidv4();
      const now = new Date().toISOString();

      const newUser: User = {
        id: userId,
        firstName,
        lastName,
        age: 18, // Default age for OAuth users
        email: tokenData.email,
        password: '', // No password for OAuth users
        provider: 'google',
        providerId: tokenData.uid,
        createdAt: now,
        updatedAt: now,
        isActive: true,
        failedLoginAttempts: 0,
      };

      // Save to Firestore
      await db.collection(COLLECTIONS.USERS).doc(userId).set(newUser);

      logger.info(`New Google user created: ${userId}`);

      return {
        user: toUserResponse(newUser),
        isNewUser: true,
      };
    }
  } catch (error) {
    logger.error('Error logging in with Google', error);
    throw error;
  }
}
