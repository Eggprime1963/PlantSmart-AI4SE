/**
 * Email Service
 *
 * Centralized email sending    // Extended timeout configuration for better reliability
    connectionTimeout: 30000,  // 30 seconds to establish connection
    greetingTimeout: 30000,   // 30 seconds to receive SMTP greeting
    socketTimeout: 30000,     // 30 seconds for socket operations

    // Simplified TLS configuration
    tls: {
      rejectUnauthorized: false  // Allow self-signed certificates for testing
    },

    // Debug settings for troubleshooting
    debug: process.env.NODE_ENV !== 'production',
    logger: process.env.NODE_ENV !== 'production'for the Plant Monitoring System
 * Uses nodemailer for SMTP email delivery with rate limiting
 */

const nodemailer = require('nodemailer');
const { SystemLog } = require('../models');

// Email configuration cache
let transporter = null;
let lastTransporterCreated = null;

// Email queue implementation to prevent simultaneous sends
const emailQueue = [];
let isProcessingQueue = false;
const EMAIL_RATE_LIMIT_MS = 1000; // 1 second between emails
let lastEmailSent = 0;

/**
 * Create and configure the email transporter
 * @returns {Object} Configured nodemailer transporter
 */
const createTransporter = () => {
  // Log the email configuration attempt
  console.log('[EMAIL] Creating email transporter');

  // Check for required environment variables
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASSWORD ) {
    const errorMsg = 'Missing email configuration: EMAIL_USER or EMAIL_PASSWORD  environment variables not set';
    console.error(`[EMAIL ERROR] ${errorMsg}`);
    SystemLog.error('emailService', 'createTransporter', errorMsg).catch(err => {
      console.error('[SYSTEM] Failed to log email configuration error:', err);
    });
    throw new Error(errorMsg);
  }

  // Create the transporter with provided configuration
  const isGmail = (process.env.EMAIL_HOST || 'smtp.gmail.com') === 'smtp.gmail.com';
  
  // Base configuration
  const transporterConfig = {
    service: isGmail ? 'gmail' : undefined,
    host: !isGmail ? process.env.EMAIL_HOST : 'smtp.gmail.com',
    port: process.env.EMAIL_PORT || 465,
    secure: true, // Use secure connection for port 465
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASSWORD,
    },
    pool: false,  // Disable connection pooling for more reliable connections
    maxMessages: 100, // Maximum number of messages to send before closing a connection
    rateDelta: 1000, // Minimum time between messages in ms
    rateLimit: 3, // Max 3 messages per rateDelta
    // Connection timeout handling
    connectionTimeout: 10000, // 10 seconds to establish connection
    greetingTimeout: 5000,   // 5 seconds to receive SMTP greeting
    socketTimeout: 10000,    // 10 seconds for socket operations
    // SSL/TLS configuration for port 465
    tls: {
      rejectUnauthorized: true, // Verify SSL certificates
      minVersion: 'TLSv1.2',    // Use modern TLS
      ciphers: 'HIGH:MEDIUM:!aNULL:!MD5:!RC4',  // Strong SSL cipher suite
      secureProtocol: 'TLSv1_2_method'  // Force TLS 1.2
    },
    // Gmail-specific settings
    service: process.env.EMAIL_HOST === 'smtp.gmail.com' ? 'gmail' : undefined,
    secure: true, // Enable SSL/TLS
    requireTLS: false // Always use TLS
  };

  // Add debug options in development environment
  if (process.env.NODE_ENV !== 'production') {
    transporterConfig.debug = true;
    transporterConfig.logger = true;
  }

  lastTransporterCreated = Date.now();
  return nodemailer.createTransport(transporterConfig);
};

/**
 * Get the transporter instance (create if doesn't exist or is stale)
 * @returns {Object} Nodemailer transporter
 */
const getTransporter = () => {
  // If no transporter exists or it's been more than 15 minutes since last creation, create a new one
  if (!transporter || !lastTransporterCreated || Date.now() - lastTransporterCreated > 15 * 60 * 1000) {
    transporter = createTransporter();
  }
  return transporter;
};

/**
 * Process the email queue to ensure rate limiting
 */
const processEmailQueue = async () => {
  // If already processing or queue is empty, do nothing
  if (isProcessingQueue || emailQueue.length === 0) {
    return;
  }

  isProcessingQueue = true;

  try {
    // Process emails with rate limiting
    while (emailQueue.length > 0) {
      const { mailOptions, resolve, reject } = emailQueue.shift();

      // Calculate time to wait before sending next email
      const now = Date.now();
      const timeToWait = Math.max(0, EMAIL_RATE_LIMIT_MS - (now - lastEmailSent));

      if (timeToWait > 0) {
        await new Promise(resolve => setTimeout(resolve, timeToWait));
      }

      try {
        // Verify connection before sending
        const isConnected = await verifyConnection();
        if (!isConnected) {
          throw new Error('Unable to establish SMTP connection after retries');
        }

        // Get or create transporter
        const emailTransporter = getTransporter();

        // Send the email
        console.log(`[EMAIL] Processing queued email to ${mailOptions.to} with subject "${mailOptions.subject}"`);
        const info = await emailTransporter.sendMail(mailOptions);

        // Update last sent timestamp
        lastEmailSent = Date.now();

        // Log success
        console.log(`[EMAIL] Email sent successfully: ${info.messageId}`);

        // Log to system logs
        await SystemLog.info('emailService', 'sendEmail', `Email sent to ${mailOptions.to}`);

        resolve(info);
      } catch (error) {
        // Log detailed error information
        const errorDetails = {
          name: error.name,
          code: error.code,
          command: error.command,
          response: error.response,
          responseCode: error.responseCode,
        };
        console.error(`[EMAIL ERROR] Failed to send email to ${mailOptions.to}:`, error.message);
        console.error('[EMAIL ERROR] Detailed error information:', errorDetails);

        // Log specific error handling advice
        if (error.code === 'ECONNECTION' || error.code === 'ETIMEDOUT') {
          console.error('[EMAIL ERROR] Connection issue - Check network/firewall settings and verify EMAIL_HOST is correct');
        } else if (error.code === 'EAUTH') {
          console.error('[EMAIL ERROR] Authentication failed - Verify EMAIL_USER and EMAIL_PASSWORD are correct');
          if (process.env.EMAIL_HOST === 'smtp.gmail.com') {
            console.error('[EMAIL ERROR] For Gmail: Make sure to use an App Password if 2FA is enabled');
          }
        } else if (error.responseCode >= 500) {
          console.error('[EMAIL ERROR] Server error - SMTP server is having issues');
        }

        // Log to system logs
        await SystemLog.error(
          'emailService',
          'sendEmail',
          `Failed to send email to ${mailOptions.to}: ${error.message}\nDetails: ${JSON.stringify(errorDetails)}`
        ).catch(err => {
          console.error('[SYSTEM] Failed to log email error:', err);
        });

        reject(error);
      }
    }
  } finally {
    isProcessingQueue = false;
  }
};

/**
 * Send an email (queued to prevent multiple simultaneous sends)
 * @param {Object} mailOptions - Email options (from, to, subject, text, html)
 * @returns {Promise<Object>} Email sending result
 */
const sendEmail = (mailOptions) => {
  return new Promise((resolve, reject) => {
    try {
      // Validate required fields
      if (!mailOptions.to || !mailOptions.subject || (!mailOptions.text && !mailOptions.html)) {
        reject(new Error('Invalid email options: missing required fields (to, subject, text/html)'));
        return;
      }

      // Set default from address if not provided
      if (!mailOptions.from) {
        mailOptions.from = process.env.EMAIL_USER;
      }

      // Add to queue
      console.log(`[EMAIL] Queueing email to ${mailOptions.to} with subject "${mailOptions.subject}"`);
      emailQueue.push({ mailOptions, resolve, reject });

      // Start processing queue if not already processing
      processEmailQueue();
    } catch (error) {
      console.error('[EMAIL ERROR] Error queueing email:', error);
      reject(error);
    }
  });
};

/**
 * Verify SMTP connection with retries
 * @param {number} retries - Number of retry attempts (default: 3)
 * @param {number} delay - Delay between retries in ms (default: 1000)
 * @returns {Promise<boolean>} True if connection is successful
 */
const verifyConnection = async (retries = 3, delay = 1000) => {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      console.log(`[EMAIL] Verifying SMTP connection (attempt ${attempt}/${retries})`);
      
      // Create a fresh transporter for each verification attempt
      transporter = null;
      const emailTransporter = getTransporter();
      
      // Test authentication and connection
      await emailTransporter.verify();
      
      console.log('[EMAIL] SMTP connection verified successfully');
      return true;
    } catch (error) {
      console.error(`[EMAIL ERROR] SMTP connection verification failed (attempt ${attempt}/${retries}):`, error);
      
      // Detailed error logging
      const errorDetails = {
        name: error.name,
        code: error.code,
        command: error.command,
        response: error.response,
        responseCode: error.responseCode,
        stack: error.stack
      };
      
      // Provide specific error guidance
      if (error.code === 'EAUTH') {
        console.error('[EMAIL ERROR] Authentication failed - Please check your email credentials');
        console.error('[EMAIL ERROR] For Gmail: Make sure to use an App Password if 2FA is enabled');
      } else if (error.code === 'ESOCKET') {
        console.error('[EMAIL ERROR] Socket error - Check your network connection and firewall settings');
      } else if (error.code === 'ECONNECTION') {
        console.error('[EMAIL ERROR] Connection error - Verify EMAIL_HOST and EMAIL_PORT are correct');
      }
      
      console.error('[EMAIL ERROR] Detailed error information:', errorDetails);

      // Log to system logs
      await SystemLog.error(
        'emailService',
        'verifyConnection',
        `SMTP verification failed (attempt ${attempt}/${retries}): ${error.message}\nDetails: ${JSON.stringify(errorDetails)}`
      ).catch(err => {
        console.error('[SYSTEM] Failed to log verification error:', err);
      });

      // If we have more retries, wait before trying again
      if (attempt < retries) {
        console.log(`[EMAIL] Waiting ${delay}ms before retry...`);
        await new Promise(resolve => setTimeout(resolve, delay));
        // Reset transporter for next attempt
        transporter = null;
      } else {
        return false;
      }
    }
  }
  return false;
};

/**
 * Send a test email to verify configuration
 * @param {string} testRecipient - Email address to send test to
 * @returns {Promise<Object>} Email sending result
 */
const sendTestEmail = async (testRecipient) => {
  const recipient = testRecipient || process.env.EMAIL_USER;

  const mailOptions = {
    to: recipient,
    subject: 'Plant Monitoring System - Email Test',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
        <h2 style="color: #4CAF50;">Email Configuration Test</h2>
        <p>This is a test email to verify that the email sending configuration is working properly.</p>
        <p>If you received this email, the email service is functioning correctly.</p>
        <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 20px 0;">
        <p style="font-size: 12px; color: #666;">This is an automated test from Plant Monitoring System</p>
        <p style="font-size: 12px; color: #666;">Environment: ${process.env.NODE_ENV || 'development'}</p>
        <p style="font-size: 12px; color: #666;">Date: ${new Date().toISOString()}</p>
      </div>
    `
  };

  return sendEmail(mailOptions);
};

module.exports = {
  sendEmail,
  verifyConnection,
  sendTestEmail
};
