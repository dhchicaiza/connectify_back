/**
 * Logger utility for application-wide logging
 */
class Logger {
  private isDevelopment: boolean;

  constructor() {
    this.isDevelopment = process.env.NODE_ENV !== 'production';
  }

  /**
   * Log info message
   * @param message - Message to log
   * @param meta - Additional metadata
   */
  info(message: string, meta?: Record<string, unknown>): void {
    console.log(`[INFO] ${new Date().toISOString()} - ${message}`, meta ? meta : '');
  }

  /**
   * Log error message
   * @param message - Error message
   * @param error - Error object
   */
  error(message: string, error?: Error | unknown): void {
    console.error(`[ERROR] ${new Date().toISOString()} - ${message}`);

    if (this.isDevelopment && error) {
      if (error instanceof Error) {
        console.error('Stack:', error.stack);
      } else {
        console.error('Error details:', error);
      }
    }
  }

  /**
   * Log warning message
   * @param message - Warning message
   * @param meta - Additional metadata
   */
  warn(message: string, meta?: Record<string, unknown>): void {
    console.warn(`[WARN] ${new Date().toISOString()} - ${message}`, meta ? meta : '');
  }

  /**
   * Log debug message (only in development)
   * @param message - Debug message
   * @param meta - Additional metadata
   */
  debug(message: string, meta?: Record<string, unknown>): void {
    if (this.isDevelopment) {
      console.debug(`[DEBUG] ${new Date().toISOString()} - ${message}`, meta ? meta : '');
    }
  }
}

export const logger = new Logger();
