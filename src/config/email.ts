import nodemailer from 'nodemailer';
import { logger } from '../utils/logger';

/**
 * Email transporter instance
 */
let transporter: nodemailer.Transporter | null = null;

/**
 * Initialize email transporter
 */
export function initializeEmailTransporter(): void {
  try {
    transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST || 'smtp.gmail.com',
      port: parseInt(process.env.EMAIL_PORT || '587'),
      secure: process.env.EMAIL_SECURE === 'true',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD,
      },
    });

    logger.info('Email transporter initialized successfully');
  } catch (error) {
    logger.error('Failed to initialize email transporter', error);
    throw error;
  }
}

/**
 * Get email transporter instance
 * @returns Email transporter
 */
export function getEmailTransporter(): nodemailer.Transporter {
  if (!transporter) {
    throw new Error('Email transporter not initialized. Call initializeEmailTransporter() first.');
  }
  return transporter;
}

/**
 * Send an email
 * @param to - Recipient email address
 * @param subject - Email subject
 * @param html - Email HTML content
 */
export async function sendEmail(to: string, subject: string, html: string): Promise<void> {
  try {
    const mailOptions = {
      from: process.env.EMAIL_FROM || 'noreply@meet.com',
      to,
      subject,
      html,
    };

    const transporter = getEmailTransporter();
    await transporter.sendMail(mailOptions);

    logger.info(`Email sent successfully to ${to}`);
  } catch (error) {
    logger.error(`Failed to send email to ${to}`, error);
    throw error;
  }
}

/**
 * Send password reset email
 * @param to - Recipient email address
 * @param resetToken - Password reset token
 */
export async function sendPasswordResetEmail(to: string, resetToken: string): Promise<void> {
  const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`;

  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>Password Reset</title>
    </head>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
      <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #4a5568;">Password Reset Request</h2>
        <p>You requested to reset your password for your Meet Platform account.</p>
        <p>Click the button below to reset your password:</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="${resetUrl}"
             style="background-color: #4299e1; color: white; padding: 12px 24px;
                    text-decoration: none; border-radius: 5px; display: inline-block;">
            Reset Password
          </a>
        </div>
        <p style="color: #718096; font-size: 14px;">
          This link will expire in 1 hour and can only be used once.
        </p>
        <p style="color: #718096; font-size: 14px;">
          If you didn't request this, please ignore this email.
        </p>
        <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 20px 0;">
        <p style="color: #a0aec0; font-size: 12px;">
          Meet Platform - Video Conference Solution
        </p>
      </div>
    </body>
    </html>
  `;

  await sendEmail(to, 'Password Reset Request', html);
}
