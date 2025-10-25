const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { User, SystemLog } = require('../models');
const emailService = require('../services/emailService');

// Email transporter has been moved to emailService.js

/**
 * Generate JWT token for authentication
 * @param {Object} user - User object
 * @returns {String} JWT token
 */
const generateToken = (user) => {
    const fullName = user.givenName && user.familyName 
        ? `${user.givenName} ${user.familyName}`
        : user.familyName || user.givenName || '';
        
    return jwt.sign(
        { 
            user_id: user.user_id, 
            email: user.email, 
            role: user.role,
            family_name: user.familyName,
            given_name: user.givenName,
            full_name: fullName
        },
        process.env.JWT_SECRET,
        { expiresIn: '1d' }
    );
};

/**
 * UC11: FORGOT PASSWORD CONTROLLER
 * =====================================
 * Implements password reset request functionality
 * 
 * Flow:
 * 1. Validate email input
 * 2. Find user by email in PostgreSQL 
 * 3. Generate JWT reset token (1-hour expiration)
 * 4. Update user's reset token fields in database
 * 5. Send professional HTML email with reset link
 * 6. Return success response (no user enumeration)
 * 
 * Security Features:
 * - JWT tokens with short expiration (1 hour)
 * - Single-use tokens (cleared after password reset)
 * - No user enumeration (same response for valid/invalid emails)
 * - Secure email templates with styling
 * 
 * Error Handling:
 * - Input validation
 * - Database connection errors
 * - Email sending failures
 * - Token generation errors
 */
// Forgot Password Controller
async function forgotPassword(req, res) {
    try {
        const { email } = req.body;
        console.log(`[PASSWORD RESET] Received request for email: ${email}`);

        // Validate email input
        if (!email) {
            return res.status(400).json({ 
                success: false,
                message: 'Email is required' 
            });
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ 
                success: false,
                message: 'Please provide a valid email address' 
            });
        }

        // Find the user by email
        const user = await User.findByEmail(email);

        // Check if user exists
        if (!user) {
            console.log(`[PASSWORD RESET] Email not registered: ${email}`);
            // Return error for non-existent email
            return res.status(404).json({
                success: false,
                message: 'No account found with this email address. Please check the email or register first.'
            });
        }

        // Generate a password reset token
        const resetToken = user.createPasswordResetToken();
        await user.updatePasswordResetFields(resetToken, user.passwordResetExpires);
        console.log(`[PASSWORD RESET] Token generated for user: ${user.email}`);

        // Create password reset URL
        const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`;

        // Email options with HTML template
        const mailOptions = {
            to: user.email,
            subject: 'Plant Monitoring System - Password Reset Request',
            text: `
                Hello ${user.family_name || 'User'},

                You requested a password reset for your Plant Monitoring System account.

                Please use this link to reset your password: ${resetUrl}

                This link will expire in 1 hour.

                If you didn't request this password reset, please ignore this email.

                ---
                This is an automated message from Plant Monitoring System. Please do not reply to this email.
            `,
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
                    <h2 style="color: #4CAF50;">Password Reset Request</h2>
                    <p>Hello ${user.family_name || 'User'},</p>
                    <p>You requested a password reset for your Plant Monitoring System account.</p>
                    <p>Please click the button below to reset your password:</p>
                    <p style="text-align: center;">
                        <a href="${resetUrl}" style="display: inline-block; background-color: #4CAF50; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-weight: bold;">Reset Password</a>
                    </p>
                    <p>This link will expire in 1 hour.</p>
                    <p>If you didn't request this password reset, please ignore this email.</p>
                    <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 20px 0;">
                    <p style="font-size: 12px; color: #666;">This is an automated message from Plant Monitoring System. Please do not reply to this email.</p>
                </div>
            `
        };

        try {
            console.log(`[PASSWORD RESET] Attempting to send email to: ${user.email}`);

            // Test email connection before sending
            const isConnected = await emailService.verifyConnection();
            if (!isConnected) {
                throw new Error('SMTP connection failed - Email service is not available');
            }

            // Use the emailService to send the email
            const emailResult = await emailService.sendEmail(mailOptions);
            console.log(`[PASSWORD RESET] Email sent with ID: ${emailResult.messageId}`);

            // Log success
            await SystemLog.info('authController', 'forgotPassword', `Password reset email sent to ${user.email}`);

            res.status(200).json({
                success: true,
                message: 'Password reset email sent successfully',
                data: {
                    email: user.email,
                    expiresIn: '1 hour'
                }
            });
        } catch (emailError) {
            // Log the email sending error with detailed diagnostics
            console.error(`[PASSWORD RESET] Email sending failed: ${emailError.message}`);

            // Add specific error diagnostics
            if (emailError.code === 'ECONNECTION' || emailError.code === 'ETIMEDOUT') {
                console.error('[PASSWORD RESET] Connection issue - Check network/firewall settings');
            } else if (emailError.code === 'EAUTH') {
                console.error('[PASSWORD RESET] Authentication failed - Check email credentials');
            }

            await SystemLog.error('authController', 'forgotPassword', `Failed to send password reset email: ${emailError.message}`);

            res.status(500).json({
                success: false,
                message: 'Failed to send password reset email. Please try again later or contact support.'
            });
        }
    } catch (error) {
        console.error('Password reset error:', error);
        await SystemLog.error('authController', 'forgotPassword', error.message);

        res.status(500).json({
            success: false,
            message: 'An error occurred during the password reset process'
        });
    }
}

// Reset Password Controller
async function resetPassword(req, res) {
    try {
        const { token } = req.query;
        const { password, confirmPassword } = req.body;

        // Validate inputs
        if (!token) {
            return res.status(400).json({ 
                error: 'Reset token is required' 
            });
        }

        if (!password || !confirmPassword) {
            return res.status(400).json({ 
                error: 'Password and confirm password are required' 
            });
        }

        if (password !== confirmPassword) {
            return res.status(400).json({ 
                error: 'Passwords do not match' 
            });
        }

        if (password.length < 6) {
            return res.status(400).json({ 
                error: 'Password must be at least 6 characters long' 
            });
        }

        // Verify the token
        let decodedToken;
        try {
            decodedToken = jwt.verify(token, process.env.JWT_SECRET);
        } catch (error) {
            return res.status(401).json({ 
                error: 'Invalid or expired password reset token' 
            });
        }

        // Find the user with the given token
        const user = await User.findByResetToken(token);

        if (!user || user.user_id !== decodedToken.id) {
            return res.status(401).json({ 
                error: 'Invalid or expired password reset token' 
            });
        }

        // Update the user's password and remove the reset token
        await user.updatePassword(password);

        // Send confirmation email with HTML template
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: 'Plant Monitoring System - Password Reset Confirmation',
            text: `
                Hello ${user.family_name || 'User'},

                Your password has been successfully reset for your Plant Monitoring System account.

                If you did not initiate this request, please contact our support team immediately.

                For your security, we recommend:
                - Using a strong, unique password
                - Enabling two-factor authentication if available
                - Keeping your login credentials secure

                ---
                This is an automated message from Plant Monitoring System. Please do not reply to this email.
            `,
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
                    <h2 style="color: #4CAF50;">Password Reset Successful</h2>
                    <p>Hello ${user.family_name || 'User'},</p>
                    <p>Your password has been successfully reset for your Plant Monitoring System account.</p>
                    <p>If you did not initiate this request, please contact our support team immediately.</p>
                    <div style="background-color: #f9f9f9; padding: 15px; border-left: 4px solid #4CAF50; margin: 15px 0;">
                        <p><strong>For your security, we recommend:</strong></p>
                        <ul>
                            <li>Using a strong, unique password</li>
                            <li>Enabling two-factor authentication if available</li>
                            <li>Keeping your login credentials secure</li>
                        </ul>
                    </div>
                    <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 20px 0;">
                    <p style="font-size: 12px; color: #666;">This is an automated message from Plant Monitoring System. Please do not reply to this email.</p>
                </div>
            `
        };

        try {
            console.log(`[EMAIL DEBUG] Attempting to send password reset confirmation email to: ${user.email}`);
            
            // Test email connection before sending
            const isConnected = await emailService.verifyConnection();
            if (!isConnected) {
                throw new Error('SMTP connection failed - Email service is not available');
            }

            // Use the emailService to send the email
            const info = await emailService.sendEmail(mailOptions);
            console.log(`[EMAIL DEBUG] Reset confirmation email sent successfully: ${info.messageId}`);

            // Log success
            await SystemLog.info('authController', 'resetPassword', `Password reset confirmation email sent to ${user.email}`);
        } catch (emailError) {
            console.error('[EMAIL DEBUG] Failed to send confirmation email:', emailError);
            await SystemLog.error('authController', 'resetPassword', `Failed to send confirmation email: ${emailError.message}`);
            // Don't fail the request if confirmation email fails
        }

        res.status(200).json({ 
            message: 'Password reset successful. You can now login with your new password.' 
        });

    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({ 
            error: 'Failed to reset password. Please try again later.' 
        });
    }
}

/**
 * UC12: CHANGE PASSWORD CONTROLLER
 * =====================================
 * Allows authenticated users to change their password
 * Requires current password verification
 * 
 * Route: PUT /auth/change-password
 * Access: Private (requires authentication)
 * 
 * Request Body:
 * - currentPassword: User's current password
 * - newPassword: New password to set
 * 
 * Response:
 * - 200 OK: Password successfully changed
 * - 400 Bad Request: Missing inputs or validation errors
 * - 401 Unauthorized: Current password incorrect
 * - 404 Not Found: User not found
 * - 500 Server Error: Internal error
 */
async function changePassword(req, res) {
    try {
        const userId = req.user.user_id; // From auth middleware
        const { currentPassword, newPassword, confirmPassword } = req.body;

        // Validate inputs
        if (!currentPassword || !newPassword || !confirmPassword) {
            return res.status(400).json({ 
                error: 'Current password, new password, and password confirmation are required' 
            });
        }
        
        // Check if new password and confirmation match
        if (newPassword !== confirmPassword) {
            return res.status(400).json({ 
                error: 'New password and confirmation password do not match' 
            });
        }

        // Find the user
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ 
                error: 'User not found' 
            });
        }

        // Verify current password
        const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ 
                error: 'Current password is incorrect' 
            });
        }

        // Check password strength
        if (newPassword.length < 8) {
            return res.status(400).json({ 
                error: 'New password must be at least 8 characters long' 
            });
        }

        // Update password
        await user.updatePassword(newPassword);

        res.status(200).json({ 
            success: true,
            message: 'Password changed successfully' 
        });

    } catch (error) {
        console.error('Change password error:', error);
        res.status(500).json({ 
            error: 'Failed to change password. Please try again later.' 
        });
    }
}

/**
 * UC1: USER REGISTRATION CONTROLLER
 * =====================================
 * Implements user account creation with email verification
 * 
 * Flow:
 * 1. Validate user input (email, password, fullName)
 * 2. Check if email already exists
 * 3. Create new user with hashed password
 * 4. Send welcome email with verification link
 * 5. Return success with user data and token
 * 
 * Security Features:
 * - Password hashing with bcrypt
 * - Email format validation
 * - Password strength requirements
 * - SQL injection protection via parameterized queries
 * 
 * Error Handling:
 * - Input validation
 * - Email uniqueness check
 * - Database errors
 * - Email sending failures
 */
async function register(req, res) {
    try {
        const { email, password, familyName, givenName } = req.body;
        console.log(`[REGISTER] Registration attempt for email: ${email}`);

        // Check if user already exists
        try {
            const existingUser = await User.findByEmail(email);
            if (existingUser) {
                console.log(`[REGISTER] Email already registered: ${email}`);
                return res.status(409).json({
                    success: false,
                    message: 'Email already registered'
                });
            }
        } catch (lookupError) {
            console.error(`[REGISTER] Error checking for existing user: ${lookupError.message}`);
            // Continue with registration attempt
        }

        console.log(`[REGISTER] Creating new user with email: ${email}`);

        // Create new user
        const userData = {
            email,
            password,
            familyName,
            givenName,
            role: 'Regular',
            notification_prefs: {}
        };

        // Save with explicit error handling
        try {
            const newUser = new User(userData);
            const savedUser = await newUser.save();
            console.log(`[REGISTER] User successfully saved with ID: ${savedUser.user_id}`);

            // Generate JWT token
            const token = generateToken(savedUser);

            // Send welcome email asynchronously (don't await to avoid blocking)
            sendWelcomeEmail(savedUser).catch(emailError => {
                console.error('[REGISTER] Welcome email could not be sent:', emailError.message);
            });

            return res.status(201).json({
                success: true,
                message: 'Registration successful',
                data: {
                    user: {
                        user_id: savedUser.user_id,
                        email: savedUser.email,
                        family_name: savedUser.family_name,
                        given_name: savedUser.given_name,
                        role: savedUser.role
                    },
                    token
                }
            });
        } catch (saveError) {
            console.error(`[REGISTER] Database error during user creation: ${saveError.message}`);

            // Handle specific error cases
            if (saveError.status === 409 || saveError.code === '23505') {
                return res.status(409).json({
                    success: false,
                    message: 'Email already registered'
                });
            }

            throw saveError; // Re-throw to be caught by outer try-catch
        }
    } catch (error) {
        console.error('[REGISTER] Registration error:', error);

        return res.status(500).json({
            success: false,
            message: 'Registration failed. Please try again later.'
        });
    }
}

/**
 * Send welcome email to newly registered user
 */
async function sendWelcomeEmail(user) {
    try {
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: 'Welcome to Plant Monitoring System',
            text: `
                Hello ${user.family_name},

                Thank you for registering with the Plant Monitoring System!

                Your account has been successfully created.

                You can now log in to access all features of our platform.

                Best regards,
                The Plant Monitoring System Team
            `,
        };

        console.log(`[EMAIL DEBUG] Attempting to send welcome email to: ${user.email}`);
        
        // Test email connection before sending
        const isConnected = await emailService.verifyConnection();
        if (!isConnected) {
            throw new Error('SMTP connection failed - Email service is not available');
        }

        // Use the emailService to send the email
        const info = await emailService.sendEmail(mailOptions);
        console.log(`[EMAIL DEBUG] Welcome email sent successfully: ${info.messageId}`);

        // Log success
        await SystemLog.info('authController', 'sendWelcomeEmail', `Welcome email sent to ${user.email}`);
    } catch (error) {
        console.error('[EMAIL DEBUG] Error sending welcome email:', error.message);
        console.error('[EMAIL DEBUG] Full error:', error);
        await SystemLog.error('authController', 'sendWelcomeEmail', `Failed to send welcome email: ${error.message}`);
        // We don't throw the error as this shouldn't stop registration
    }
}

/**
 * UC2: USER LOGIN CONTROLLER
 * =====================================
 * Implements user authentication with JWT token generation
 * 
 * Flow:
 * 1. Validate user input (email, password)
 * 2. Find user by email
 * 3. Validate password
 * 4. Generate JWT token
 * 5. Return success with user data and token
 * 
 * Security Features:
 * - Secure password comparison with bcrypt
 * - JWT token with user ID and role
 * - No sensitive data exposure
 * 
 * Error Handling:
 * - Input validation
 * - User not found
 * - Invalid credentials
 * - Database errors
 */
async function login(req, res) {
    try {
        const { email, password } = req.body;
        console.log(`[LOGIN] Attempt for email: ${email}`);

        // Validate inputs
        if (!email || !password) {
            console.log('[LOGIN] Missing email or password');
            return res.status(400).json({
                error: 'Email and password are required'
            });
        }

        // Find user by email
        const user = await User.findByEmail(email);
        if (!user) {
            console.log(`[LOGIN] User not found: ${email}`);
            return res.status(401).json({
                error: 'Invalid email or password'
            });
        }

        console.log(`[LOGIN] User found: ${user.email}, checking password...`);
        // Improved safer debug logging without exposing passwords
        console.log(`[LOGIN] User object has password hash: ${!!user.password}`);
        console.log(`[LOGIN] Password hash type: ${typeof user.password}`);
        console.log(`[LOGIN] Password hash length: ${user.password ? user.password.length : 'N/A'}`);
        console.log(`[LOGIN] Input password provided: ${!!password}`);

        // Validate password
        const isPasswordValid = await user.validatePassword(password);
        console.log(`[LOGIN] Password validation result: ${isPasswordValid}`);

        if (!isPasswordValid) {
            return res.status(401).json({
                error: 'Invalid email or password'
            });
        }

        // Generate JWT token
        const token = generateToken(user);
        console.log(`[LOGIN] Success for user: ${user.email}`);
        
        // Include both name fields for proper display
        const fullName = user.givenName && user.familyName 
            ? `${user.givenName} ${user.familyName}`
            : user.familyName || user.givenName || 'User';
            
        console.log(`[LOGIN] User name fields: given_name=${user.givenName}, family_name=${user.familyName}, fullName=${fullName}`);
        
        // Create user response object
        const userData = {
            user_id: user.user_id,
            email: user.email,
            family_name: user.familyName,
            given_name: user.givenName,
            full_name: fullName,
            role: user.role
        };
        
        console.log(`[LOGIN] User data being sent to client:`, JSON.stringify(userData));

        res.status(200).json({
            success: true,
            message: 'Login successful',
            data: {
                user: userData,
                token
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            error: 'Login failed. Please try again later.'
        });
    }
}

/**
 * UC3: USER LOGOUT CONTROLLER
 * =====================================
 * Implements user logout functionality
 * 
 * Note: Since we're using JWT tokens which are stateless,
 * actual token invalidation would require additional infrastructure
 * like a token blacklist in Redis or similar.
 * 
 * This function serves mainly as a hook for client-side logout.
 */
async function logout(req, res) {
    try {
        // Since JWT is stateless, we can't invalidate tokens server-side without additional infrastructure
        // In a production app, we would maintain a blacklist of tokens in Redis or similar

        // Log the logout action (could be saved to SystemLog in a real implementation)
        console.log(`User logged out: ${req.user ? req.user.user_id : 'Unknown'}`);

        res.status(200).json({
            success: true,
            message: 'Logout successful'
        });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({
            error: 'Logout failed. Please try again later.'
        });
    }
}

module.exports = {
    register,
    login,
    logout,
    forgotPassword,
    resetPassword,
    changePassword,
};
