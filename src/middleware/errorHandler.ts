import { Request, Response, NextFunction } from 'express';
import { AppError } from '../utils/customErrors';
import { logger } from '../utils/logger';
import { sendError } from '../utils/responseFormatter';

/**
 * Global error handler middleware
 * Handles all errors thrown in the application
 */
export function errorHandler(
  err: Error | AppError,
  req: Request,
  res: Response,
  _next: NextFunction
): void {
  // Log the error
  logger.error(`Error in ${req.method} ${req.path}`, err);

  // Handle operational errors
  if (err instanceof AppError && err.isOperational) {
    sendError(res, err.statusCode, err.message);
    return;
  }

  // Handle programming or unknown errors
  const statusCode = 500;
  const message =
    process.env.NODE_ENV === 'production'
      ? 'An unexpected error occurred. Please try again later.'
      : err.message || 'Internal server error';

  sendError(res, statusCode, message);
}

/**
 * Handle 404 Not Found errors
 */
export function notFoundHandler(req: Request, res: Response): void {
  sendError(res, 404, `Route ${req.method} ${req.path} not found`);
}

/**
 * Async handler wrapper to catch errors in async route handlers
 * @param fn - Async function to wrap
 */
export function asyncHandler(
  fn: (req: Request, res: Response, next: NextFunction) => Promise<unknown>
) {
  return (req: Request, res: Response, next: NextFunction): void => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}
