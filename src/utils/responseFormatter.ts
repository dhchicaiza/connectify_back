import { Response } from 'express';

/**
 * Success response structure
 */
interface SuccessResponse<T> {
  success: true;
  data: T;
  message?: string;
}

/**
 * Error response structure
 */
interface ErrorResponse {
  success: false;
  error: {
    message: string;
    code?: string;
  };
}

/**
 * Format successful response
 * @param res - Express response object
 * @param statusCode - HTTP status code
 * @param data - Response data
 * @param message - Optional success message
 */
export function sendSuccess<T>(
  res: Response,
  statusCode: number,
  data: T,
  message?: string
): Response {
  const response: SuccessResponse<T> = {
    success: true,
    data,
    ...(message && { message }),
  };

  return res.status(statusCode).json(response);
}

/**
 * Format error response
 * @param res - Express response object
 * @param statusCode - HTTP status code
 * @param message - Error message
 * @param code - Optional error code
 */
export function sendError(
  res: Response,
  statusCode: number,
  message: string,
  code?: string
): Response {
  const response: ErrorResponse = {
    success: false,
    error: {
      message,
      ...(code && { code }),
    },
  };

  return res.status(statusCode).json(response);
}
