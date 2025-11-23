/**
 * User model interface for Firestore
 */
export interface User {
  id: string;
  firstName: string;
  lastName: string;
  age: number;
  email: string;
  password: string; // Hashed with bcrypt
  provider: 'email' | 'google' | 'facebook' | 'github';
  providerId?: string; // OAuth provider ID
  createdAt: string; // ISO-8601 format
  updatedAt: string; // ISO-8601 format
  isActive: boolean;
  failedLoginAttempts?: number;
  lockUntil?: string; // ISO-8601 format
}

/**
 * User creation data (for signup)
 */
export interface CreateUserData {
  firstName: string;
  lastName: string;
  age: number;
  email: string;
  password: string;
  provider?: 'email' | 'google' | 'facebook' | 'github';
  providerId?: string;
}

/**
 * User update data (for profile editing)
 */
export interface UpdateUserData {
  firstName?: string;
  lastName?: string;
  age?: number;
  email?: string;
}

/**
 * User response (without sensitive data)
 */
export interface UserResponse {
  id: string;
  firstName: string;
  lastName: string;
  age: number;
  email: string;
  provider: 'email' | 'google' | 'facebook' | 'github';
  createdAt: string;
  updatedAt: string;
}

/**
 * Convert User to UserResponse (remove sensitive data)
 * @param user - User object
 * @returns UserResponse object
 */
export function toUserResponse(user: User): UserResponse {
  return {
    id: user.id,
    firstName: user.firstName,
    lastName: user.lastName,
    age: user.age,
    email: user.email,
    provider: user.provider,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
  };
}
