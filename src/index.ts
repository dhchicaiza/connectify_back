import express, { Application } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';
import { initializeFirebase } from './config/firebase';
import { initializeEmailTransporter } from './config/email';
import { errorHandler, notFoundHandler } from './middleware/errorHandler';
import { logger } from './utils/logger';
import authRoutes from './routes/auth.routes';
import usersRoutes from './routes/users.routes';
import meetingsRoutes from './routes/meetings.routes';

// Load environment variables
dotenv.config();

// Initialize Express app
const app: Application = express();
const PORT = process.env.PORT || 3000;

/**
 * Initialize application services
 */
function initializeServices(): void {
  try {
    // Initialize Firebase
    initializeFirebase();

    // Initialize Email transporter
    initializeEmailTransporter();

    logger.info('All services initialized successfully');
  } catch (error) {
    logger.error('Failed to initialize services', error);
    process.exit(1);
  }
}

/**
 * Configure Express middleware
 */
function configureMiddleware(): void {
  // Security middleware
  app.use(helmet());

  // CORS configuration
  const allowedOrigins = process.env.CORS_ORIGIN
    ? process.env.CORS_ORIGIN.split(',').map((origin) => origin.trim())
    : [];

  // In development, also allow localhost origins
  const isDevelopment = process.env.NODE_ENV === 'development';
  const developmentOrigins = [
    'http://localhost:5173',
    'http://localhost:3000',
    'http://localhost:5174',
    'http://127.0.0.1:5173',
  ];

  app.use(
    cors({
      origin: (origin, callback) => {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) {
          return callback(null, true);
        }

        // Normalize origin (remove trailing slash)
        const normalizedOrigin = origin.endsWith('/') ? origin.slice(0, -1) : origin;

        // Check if origin is in allowed list (with or without trailing slash)
        const isAllowed = allowedOrigins.some((allowed) => {
          const normalizedAllowed = allowed.endsWith('/') ? allowed.slice(0, -1) : allowed;
          return normalizedAllowed === normalizedOrigin || allowed === origin;
        });

        // In development, also check localhost origins
        if (isDevelopment && developmentOrigins.includes(normalizedOrigin)) {
          return callback(null, true);
        }

        // If no origins configured, allow all in development
        if (allowedOrigins.length === 0) {
          if (isDevelopment) {
            logger.warn('CORS: No origins configured, allowing all in development');
            return callback(null, true);
          }
          logger.warn('CORS: No origins configured in production, blocking request');
          return callback(new Error('CORS not configured'));
        }

        if (isAllowed) {
          return callback(null, true);
        }

        logger.warn(`CORS blocked request from origin: ${origin}`);
        return callback(new Error('Not allowed by CORS'));
      },
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization'],
      preflightContinue: false,
      optionsSuccessStatus: 204,
    })
  );

  // Body parser middleware
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));

  // Request logging middleware (only in development)
  if (process.env.NODE_ENV === 'development') {
    app.use((req, _res, next) => {
      logger.debug(`${req.method} ${req.path}`);
      next();
    });
  }
}

/**
 * Configure application routes
 */
function configureRoutes(): void {
  // Health check endpoint
  app.get('/health', (_req, res) => {
    res.status(200).json({
      success: true,
      message: 'Server is running',
      timestamp: new Date().toISOString(),
    });
  });

  // API routes
  app.use('/api/auth', authRoutes);
  app.use('/api/users', usersRoutes);
  app.use('/api/meetings', meetingsRoutes);

  // 404 handler (must be after all routes)
  app.use(notFoundHandler);

  // Error handler (must be last)
  app.use(errorHandler);
}

/**
 * Start the Express server
 */
function startServer(): void {
  app.listen(PORT, () => {
    logger.info(`Server is running on port ${PORT}`);
    logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
  });
}

/**
 * Initialize and start the application
 */
function bootstrap(): void {
  try {
    initializeServices();
    configureMiddleware();
    configureRoutes();
    startServer();
  } catch (error) {
    logger.error('Failed to start server', error);
    process.exit(1);
  }
}

// Start the application
bootstrap();

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason: unknown) => {
  logger.error('Unhandled Promise Rejection', reason);
  process.exit(1);
});

// Handle uncaught exceptions
process.on('uncaughtException', (error: Error) => {
  logger.error('Uncaught Exception', error);
  process.exit(1);
});

export default app;
