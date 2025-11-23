import { Response } from 'express';
import { AuthRequest } from '../middleware/auth';
import * as authService from '../services/auth.service';
import { generateToken } from '../middleware/auth';
import { sendSuccess } from '../utils/responseFormatter';
import { BadRequestError } from '../utils/customErrors';
import {
  isValidEmail,
  isValidPassword,
  isValidAge,
  isValidName,
  getPasswordError,
  sanitizeString,
} from '../utils/validators';
import { logger } from '../utils/logger';

/**
 * Sign-up endpoint - H1
 * POST /api/auth/signup
 */
export async function signup(req: AuthRequest, res: Response): Promise<Response> {
  try {
    const { firstName, lastName, age, email, password, confirmPassword } = req.body;

    // Validate required fields
    if (!firstName || !lastName || !age || !email || !password || !confirmPassword) {
      throw new BadRequestError('All fields are required');
    }

    // Sanitize inputs
    const sanitizedFirstName = sanitizeString(firstName);
    const sanitizedLastName = sanitizeString(lastName);
    const sanitizedEmail = sanitizeString(email).toLowerCase();

    // Validate names
    if (!isValidName(sanitizedFirstName)) {
      throw new BadRequestError('First name must contain only letters and be 2-50 characters long');
    }

    if (!isValidName(sanitizedLastName)) {
      throw new BadRequestError('Last name must contain only letters and be 2-50 characters long');
    }

    // Validate age
    if (!isValidAge(age)) {
      throw new BadRequestError('Age must be at least 13');
    }

    // Validate email
    if (!isValidEmail(sanitizedEmail)) {
      throw new BadRequestError('Invalid email format');
    }

    // Validate password
    if (!isValidPassword(password)) {
      const passwordError = getPasswordError(password);
      throw new BadRequestError(passwordError || 'Invalid password');
    }

    // Validate password confirmation
    if (password !== confirmPassword) {
      throw new BadRequestError('Passwords do not match');
    }

    // Create user
    const user = await authService.createUser({
      firstName: sanitizedFirstName,
      lastName: sanitizedLastName,
      age,
      email: sanitizedEmail,
      password,
    });

    return sendSuccess(res, 201, { id: user.id }, 'Account created successfully');
  } catch (error) {
    logger.error('Signup error', error);
    throw error;
  }
}

/**
 * Login endpoint - H2
 * POST /api/auth/login
 */
export async function login(req: AuthRequest, res: Response): Promise<Response> {
  try {
    const { email, password } = req.body;

    // Validate required fields
    if (!email || !password) {
      throw new BadRequestError('Email and password are required');
    }

    // Sanitize email
    const sanitizedEmail = sanitizeString(email).toLowerCase();

    // Validate email format
    if (!isValidEmail(sanitizedEmail)) {
      throw new BadRequestError('Invalid email format');
    }

    // Login user
    const user = await authService.loginUser(sanitizedEmail, password);

    // Generate JWT token
    const token = generateToken({
      userId: user.id,
      email: user.email,
    });

    return sendSuccess(
      res,
      200,
      {
        token,
        user,
      },
      'Login successful'
    );
  } catch (error) {
    logger.error('Login error', error);
    throw error;
  }
}

/**
 * Logout endpoint - H2
 * POST /api/auth/logout
 */
export async function logout(req: AuthRequest, res: Response): Promise<Response> {
  try {
    // Note: JWT tokens are stateless, so logout is handled on the client side
    // by removing the token from storage. This endpoint is mainly for logging purposes.

    if (req.user) {
      logger.info(`User logged out: ${req.user.userId}`);
    }

    return sendSuccess(res, 200, null, 'Logout successful');
  } catch (error) {
    logger.error('Logout error', error);
    throw error;
  }
}

/**
 * Forgot password endpoint - H3
 * POST /api/auth/forgot-password
 */
export async function forgotPassword(req: AuthRequest, res: Response): Promise<Response> {
  try {
    const { email } = req.body;

    // Validate required field
    if (!email) {
      throw new BadRequestError('Email is required');
    }

    // Sanitize email
    const sanitizedEmail = sanitizeString(email).toLowerCase();

    // Validate email format
    if (!isValidEmail(sanitizedEmail)) {
      throw new BadRequestError('Invalid email format');
    }

    // Request password reset (always returns success to prevent email enumeration)
    await authService.requestPasswordReset(sanitizedEmail);

    // Return generic success message
    return sendSuccess(
      res,
      202,
      null,
      'If an account exists with this email, a password reset link has been sent'
    );
  } catch (error) {
    logger.error('Forgot password error', error);
    throw error;
  }
}

/**
 * Reset password endpoint - H3
 * POST /api/auth/reset-password
 */
export async function resetPassword(req: AuthRequest, res: Response): Promise<Response> {
  try {
    const { token, password, confirmPassword } = req.body;

    // Validate required fields
    if (!token || !password || !confirmPassword) {
      throw new BadRequestError('All fields are required');
    }

    // Validate password
    if (!isValidPassword(password)) {
      const passwordError = getPasswordError(password);
      throw new BadRequestError(passwordError || 'Invalid password');
    }

    // Validate password confirmation
    if (password !== confirmPassword) {
      throw new BadRequestError('Passwords do not match');
    }

    // Reset password
    await authService.resetPassword(token, password);

    return sendSuccess(res, 200, null, 'Password reset successful');
  } catch (error) {
    logger.error('Reset password error', error);
    throw error;
  }
}

/**
 * Google Sign-In endpoint controller (User Story H2 - OAuth Login)
 *
 * @async
 * @function googleSignIn
 * @route POST /api/auth/google
 * @access Public
 * @rateLimit 5 requests per 10 minutes (loginRateLimiter)
 *
 * @param {AuthRequest} req - Express request object
 * @param {string} req.body.idToken - Google ID token from Firebase Authentication client SDK
 * @param {Response} res - Express response object
 *
 * @returns {Promise<Response>} HTTP 200 with JWT token and user data
 * @returns {boolean} response.data.success - Always true on success
 * @returns {Object} response.data.data - Response payload
 * @returns {string} response.data.data.token - JWT token for API authentication
 * @returns {UserResponse} response.data.data.user - User information (without password)
 * @returns {boolean} response.data.data.isNewUser - Whether this is a newly created account
 * @returns {string} response.data.message - Success message
 *
 * @throws {BadRequestError} 400 - If idToken is missing from request body
 * @throws {UnauthorizedError} 401 - If Google token is invalid or verification fails
 * @throws {TooManyRequestsError} 429 - If rate limit exceeded (5 attempts per 10 min)
 *
 * @description
 * This endpoint implements secure Google Sign-In using Firebase ID token verification:
 *
 * **Authentication Flow:**
 * 1. Receives Google ID token from frontend (obtained via Firebase Auth client SDK)
 * 2. Validates that idToken is present in request body
 * 3. Calls `loginWithGoogle()` service which:
 *    - Verifies token authenticity with Firebase Admin SDK
 *    - Creates new user if email doesn't exist
 *    - Logs in existing user if email is found
 * 4. Generates JWT token for API authentication
 * 5. Returns user data and authentication token
 *
 * **Security Features:**
 * - Backend verification of Google tokens (not trusting client data)
 * - Rate limiting prevents brute force attacks
 * - Only verified Google emails accepted
 * - JWT tokens for stateless authentication
 *
 * **Response Format:**
 * - New user: "Account created successfully with Google"
 * - Existing user: "Login successful with Google"
 *
 * @example
 * // Request
 * POST /api/auth/google
 * Content-Type: application/json
 *
 * {
 *   "idToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
 * }
 *
 * @example
 * // Response (200 OK)
 * {
 *   "success": true,
 *   "data": {
 *     "token": "jwt.token.here",
 *     "user": {
 *       "id": "uuid",
 *       "firstName": "John",
 *       "lastName": "Doe",
 *       "email": "john@gmail.com",
 *       "age": 18,
 *       "provider": "google",
 *       "createdAt": "2025-01-18T00:00:00.000Z",
 *       "updatedAt": "2025-01-18T00:00:00.000Z"
 *     },
 *     "isNewUser": true
 *   },
 *   "message": "Account created successfully with Google"
 * }
 *
 * @see {@link loginWithGoogle} - Service function that handles the authentication logic
 * @see {@link verifyGoogleToken} - Function that verifies Google ID tokens
 */
export async function googleSignIn(req: AuthRequest, res: Response): Promise<Response> {
  try {
    const { idToken } = req.body;

    // Validate required field
    if (!idToken) {
      throw new BadRequestError('Google ID token is required');
    }

    // Login or create user with Google
    const { user, isNewUser } = await authService.loginWithGoogle(idToken);

    // Generate JWT token
    const token = generateToken({
      userId: user.id,
      email: user.email,
    });

    const message = isNewUser
      ? 'Account created successfully with Google'
      : 'Login successful with Google';

    return sendSuccess(
      res,
      200,
      {
        token,
        user,
        isNewUser,
      },
      message
    );
  } catch (error) {
    logger.error('Google sign-in error', error);
    throw error;
  }
}

/**
 * GitHub Sign-In endpoint controller.
 * POST /api/auth/github
 */
export async function githubSignIn(req: AuthRequest, res: Response): Promise<Response> {
  try {
    const { idToken } = req.body;

    if (!idToken) {
      throw new BadRequestError('GitHub ID token is required');
    }

    const { user, isNewUser } = await authService.loginWithGithub(idToken);

    const token = generateToken({
      userId: user.id,
      email: user.email,
    });

    const message = isNewUser
      ? 'Account created successfully with GitHub'
      : 'Login successful with GitHub';

    return sendSuccess(
      res,
      200,
      {
        token,
        user,
        isNewUser,
      },
      message
    );
  } catch (error) {
    logger.error('GitHub sign-in error', error);
    throw error;
  }
}

/**
 * OAuth callback endpoint (Facebook and legacy support) - H2
 * POST /api/auth/oauth
 * @deprecated Use /api/auth/google for Google Sign-In
 */
export async function oauthCallback(req: AuthRequest, res: Response): Promise<Response> {
  try {
    const { provider, providerId, email, firstName, lastName } = req.body;

    // Validate required fields
    if (!provider || !providerId || !email || !firstName || !lastName) {
      throw new BadRequestError('Missing required OAuth data');
    }

    // Validate provider
    if (provider !== 'google' && provider !== 'facebook') {
      throw new BadRequestError('Invalid OAuth provider');
    }

    // Sanitize inputs
    const sanitizedEmail = sanitizeString(email).toLowerCase();
    const sanitizedFirstName = sanitizeString(firstName);
    const sanitizedLastName = sanitizeString(lastName);

    // Check if user exists
    const existingUser = await authService.getUserByEmail(sanitizedEmail);

    let userResponse;

    if (existingUser) {
      // User exists, log them in
      logger.info(`OAuth login for existing user: ${existingUser.id}`);
      userResponse = await authService.getUserById(existingUser.id);
    } else {
      // Create new user
      userResponse = await authService.createUser({
        firstName: sanitizedFirstName,
        lastName: sanitizedLastName,
        age: 18, // Default age for OAuth users
        email: sanitizedEmail,
        password: providerId, // Use providerId as dummy password (won't be used for login)
        provider,
        providerId,
      });

      logger.info(`New OAuth user created: ${userResponse.id}`);
    }

    // Generate JWT token
    const token = generateToken({
      userId: userResponse.id,
      email: userResponse.email,
    });

    return sendSuccess(
      res,
      200,
      {
        token,
        user: userResponse,
      },
      'OAuth login successful'
    );
  } catch (error) {
    logger.error('OAuth callback error', error);
    throw error;
  }
}
