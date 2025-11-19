/**
 * Password reset token interface for Firestore
 */
export interface PasswordResetToken {
  id: string; // Token itself
  userId: string;
  email: string;
  createdAt: string; // ISO-8601 format
  expiresAt: string; // ISO-8601 format (1 hour from creation)
  used: boolean;
}

/**
 * Create password reset token data
 */
export interface CreatePasswordResetTokenData {
  userId: string;
  email: string;
}
