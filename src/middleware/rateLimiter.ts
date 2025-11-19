import rateLimit from 'express-rate-limit';

/**
 * Rate limiter for login attempts
 * Max 5 attempts per 10 minutes per IP
 */
export const loginRateLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '600000'), // 10 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '5'), // 5 requests
  message: 'Too many login attempts. Please try again later.',
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  skipSuccessfulRequests: false, // Don't count successful requests
  skipFailedRequests: false, // Count failed requests
});

/**
 * Rate limiter for password reset requests
 * Max 3 attempts per 15 minutes per IP
 */
export const passwordResetRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 3, // 3 requests
  message: 'Too many password reset requests. Please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

/**
 * Rate limiter for signup requests
 * Max 5 signups per hour per IP
 */
export const signupRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // 5 requests
  message: 'Too many account creation attempts. Please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

/**
 * General API rate limiter
 * Max 100 requests per 15 minutes per IP
 */
export const apiRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests
  message: 'Too many requests. Please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});
