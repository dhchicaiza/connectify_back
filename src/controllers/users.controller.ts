import { Response } from 'express';
import { AuthRequest } from '../middleware/auth';
import * as authService from '../services/auth.service';
import { sendSuccess } from '../utils/responseFormatter';
import { BadRequestError, UnauthorizedError } from '../utils/customErrors';
import {
  isValidEmail,
  isValidAge,
  isValidName,
  isValidPassword,
  getPasswordError,
  sanitizeString,
} from '../utils/validators';
import { logger } from '../utils/logger';

/**
 * Get current user profile
 * GET /api/users/me
 */
export async function getProfile(req: AuthRequest, res: Response): Promise<Response> {
  try {
    if (!req.user) {
      throw new UnauthorizedError('User not authenticated');
    }

    const user = await authService.getUserById(req.user.userId);

    return sendSuccess(res, 200, user);
  } catch (error) {
    logger.error('Get profile error', error);
    throw error;
  }
}

/**
 * Update user profile - H4
 * PUT /api/users/me
 */
export async function updateProfile(req: AuthRequest, res: Response): Promise<Response> {
  try {
    if (!req.user) {
      throw new UnauthorizedError('User not authenticated');
    }

    const { firstName, lastName, age, email, password, currentPassword } = req.body;

    // Validate that at least one field is provided
    if (!firstName && !lastName && !age && !email && !password) {
      throw new BadRequestError('At least one field must be provided for update');
    }

    const updateData: {
      firstName?: string;
      lastName?: string;
      age?: number;
      email?: string;
      password?: string;
    } = {};

    // Validate and add firstName if provided
    if (firstName !== undefined) {
      const sanitizedFirstName = sanitizeString(firstName);
      if (!isValidName(sanitizedFirstName)) {
        throw new BadRequestError('First name must contain only letters and be 2-50 characters long');
      }
      updateData.firstName = sanitizedFirstName;
    }

    // Validate and add lastName if provided
    if (lastName !== undefined) {
      const sanitizedLastName = sanitizeString(lastName);
      if (!isValidName(sanitizedLastName)) {
        throw new BadRequestError('Last name must contain only letters and be 2-50 characters long');
      }
      updateData.lastName = sanitizedLastName;
    }

    // Validate and add age if provided
    if (age !== undefined) {
      if (!isValidAge(age)) {
        throw new BadRequestError('Age must be at least 13');
      }
      updateData.age = age;
    }

    // Validate and add email if provided
    if (email !== undefined) {
      const sanitizedEmail = sanitizeString(email).toLowerCase();
      if (!isValidEmail(sanitizedEmail)) {
        throw new BadRequestError('Invalid email format');
      }
      updateData.email = sanitizedEmail;
    }

    // Validate and add password if provided
    if (password !== undefined) {
      // Require current password for security when changing password
      if (!currentPassword) {
        throw new BadRequestError('Current password is required to change password');
      }

      // Validate new password strength
      if (!isValidPassword(password)) {
        const passwordError = getPasswordError(password);
        throw new BadRequestError(passwordError || 'Invalid password');
      }

      // Verify current password before allowing change
      const isCurrentPasswordValid = await authService.verifyUserPassword(
        req.user.userId,
        currentPassword
      );

      if (!isCurrentPasswordValid) {
        throw new BadRequestError('Current password is incorrect');
      }

      updateData.password = password;
    }

    // Update user profile
    const updatedUser = await authService.updateUserProfile(req.user.userId, updateData);

    return sendSuccess(res, 200, updatedUser, 'Profile updated successfully');
  } catch (error) {
    logger.error('Update profile error', error);
    throw error;
  }
}

/**
 * Delete user account - H4 (if needed)
 * DELETE /api/users/me
 */
export async function deleteAccount(req: AuthRequest, res: Response): Promise<Response> {
  try {
    if (!req.user) {
      throw new UnauthorizedError('User not authenticated');
    }

    // Note: This is a placeholder. Actual deletion logic can be implemented later.
    // For now, we'll just mark the account as inactive or soft-delete it.

    logger.info(`Account deletion requested for user: ${req.user.userId}`);

    return sendSuccess(res, 200, null, 'Account deletion requested');
  } catch (error) {
    logger.error('Delete account error', error);
    throw error;
  }
}
