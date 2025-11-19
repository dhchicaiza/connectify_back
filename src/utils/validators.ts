/**
 * Validate email format (RFC 5322 simplified)
 * @param email - Email to validate
 * @returns True if valid, false otherwise
 */
export function isValidEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

/**
 * Validate password strength
 * Requirements: ≥8 characters, 1 uppercase, 1 lowercase, 1 number, 1 special character
 * @param password - Password to validate
 * @returns True if valid, false otherwise
 */
export function isValidPassword(password: string): boolean {
  if (password.length < 8) {
    return false;
  }

  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumber = /\d/.test(password);
  const hasSpecialChar = /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(password);

  return hasUpperCase && hasLowerCase && hasNumber && hasSpecialChar;
}

/**
 * Validate age (must be ≥13)
 * @param age - Age to validate
 * @returns True if valid, false otherwise
 */
export function isValidAge(age: number): boolean {
  return Number.isInteger(age) && age >= 13 && age <= 120;
}

/**
 * Sanitize string input (remove leading/trailing whitespace)
 * @param input - String to sanitize
 * @returns Sanitized string
 */
export function sanitizeString(input: string): string {
  return input.trim();
}

/**
 * Validate name (no numbers or special characters, 2-50 characters)
 * @param name - Name to validate
 * @returns True if valid, false otherwise
 */
export function isValidName(name: string): boolean {
  const nameRegex = /^[a-zA-ZáéíóúÁÉÍÓÚñÑ\s]{2,50}$/;
  return nameRegex.test(name);
}

/**
 * Get password validation error message
 * @param password - Password to check
 * @returns Error message or null if valid
 */
export function getPasswordError(password: string): string | null {
  if (password.length < 8) {
    return 'Password must be at least 8 characters long';
  }
  if (!/[A-Z]/.test(password)) {
    return 'Password must contain at least one uppercase letter';
  }
  if (!/[a-z]/.test(password)) {
    return 'Password must contain at least one lowercase letter';
  }
  if (!/\d/.test(password)) {
    return 'Password must contain at least one number';
  }
  if (!/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(password)) {
    return 'Password must contain at least one special character';
  }
  return null;
}
