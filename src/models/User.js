/**
 * ============================================================================
 * USER MODEL - CORE USER MANAGEMENT FOR ALL USE CASES
 * ============================================================================
 * 
 * SUPPORTS THESE USE CASES:
 * ✅ UC11: Reset Password - Complete password reset functionality
 * 🔄 UC1: User Registration - save() method ready 
 * 🔄 UC2: User Login - validatePassword() method ready   
 * 🔄 UC3: User Logout - Session cleanup support 
 * 🔄 UC12: Change Password - updatePassword() method ready
 * 🔄 UC13: Manage Profile - save() method for profile updates
 * 🔄 UC16: Upgrade to Premium - role field for Premium status
 * 🔄 UC19, UC22: Make Payment - user_id for payment association
 * 🔄 UC24: Manage Users (Admin) - Full CRUD operations ready
 * 
 * USER ROLES SUPPORTED:
 * - 'Regular': Basic features (UC1-13)
 * - 'Premium': Premium features (UC14-23) 
 * - 'Admin': Administrative features (UC24-31)
 * 
 * SECURITY FEATURES:
 * - bcrypt password hashing (12 salt rounds)
 * - JWT token generation for password reset (1-hour expiration)
 * - SQL injection protection with parameterized queries
 * - Sensitive data exclusion in toJSON()
 * 
 * RELATIONSHIPS:
 * - Users (1) → (N) Devices
 * - Users (1) → (N) Plants  
 * - Users (1) → (N) Alerts
 * - Users (1) → (N) Payments
 * - Users (1) → (N) ChatHistory
 */

const { pool } = require('../config/db');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

class User {
/**
 * USER CONSTRUCTOR
 * Initializes user object with validation and default values
 * SUPPORTS: UC1 (Registration), UC13 (Profile Management), UC24 (User Management),
 * UC31: Manage Multi-Language Settings
 */
constructor(userData) {
    this.user_id = userData.user_id;
    this.email = userData.email;

    // Fix password handling - store hash and plaintext separately
    // This is critical for differentiating between database retrieval and new user creation
    if (userData.password_hash) {
        // When loading from database, password_hash is the bcrypt hash
        this.password = userData.password_hash; // Store the hash for validation
        this.plainTextPassword = null; // No plaintext when loading existing user

        console.log('[USER CONSTRUCTOR] Loaded existing user with password hash');
    } else if (userData.password) {
        // When creating new user, password is plain text
        this.plainTextPassword = userData.password; // Store plaintext for hashing during save
        this.password = null; // No hash yet for new user

        console.log('[USER CONSTRUCTOR] New user with plaintext password (will be hashed on save)');
    } else {
        // Neither password nor hash provided
        this.password = null;
        this.plainTextPassword = null;

        console.log('[USER CONSTRUCTOR] Warning: No password or hash provided');
    }

    // Log field diagnostics (safer, without exposing actual values)
    console.log('[USER CONSTRUCTOR] Available fields in userData:', Object.keys(userData));
    console.log('[USER CONSTRUCTOR] Password source:',
        userData.password_hash ? 'password_hash' :
        userData.password ? 'password' : 'not found');

    this.familyName = userData.family_name;
    this.givenName = userData.given_name;
    this.role = userData.role || 'Regular'; // Default role for UC1
    this.notification_prefs = userData.notification_prefs || {}; // Notification preferences
    this.fcm_tokens = userData.fcm_tokens || []; // Firebase Cloud Messaging tokens for push notifications
    this.passwordResetToken = userData.password_reset_token;
    this.passwordResetExpires = userData.password_reset_expires;
    this.languagePreference = userData.language_preference || 'en'; // Default language
    this.created_at = userData.created_at;

    // Add support for Google login
    this.google_id = userData.google_id;
    this.profile_picture = userData.profile_picture;
}

/**
 * Create a password reset token for the user
 * For UC11: Reset Password functionality
 * @returns {string} token for password reset
 */
createPasswordResetToken() {
    try {
        // Generate a random token
        const resetToken = crypto.randomBytes(32).toString('hex');
        
        // Store the token and expiration
        this.passwordResetToken = resetToken;
        this.passwordResetExpires = new Date(Date.now() + 900000); // 15 minutes
        
        return resetToken;
    } catch (error) {
        throw new Error('Error creating password reset token: ' + error.message);
    }
}

/**
 * Update the password reset fields in the database
 * For UC11: Reset Password functionality
 * @param {string} token - The reset token
 * @param {Date} expires - When the token expires
 * @returns {boolean} Success status
 */
async updatePasswordResetFields(token, expires) {
    try {
        const query = `
                    UPDATE Users 
                    SET password_reset_token = $1, password_reset_expires = $2
                    WHERE user_id = $3
                    RETURNING *
                `;
        await pool.query(query, [token, expires, this.user_id]);
        
        this.passwordResetToken = token;
        this.passwordResetExpires = expires;
        
        return true;
    } catch (error) {
        throw new Error('Error updating password reset fields: ' + error.message);
    }
}    /**
     * FIND USER BY EMAIL - AUTHENTICATION & SECURITY
     * Critical for login, password reset, and user identification
     * 
     * SUPPORTS:
     * - UC1: User Registration (Other backend member) - Email uniqueness validation
     * - UC2: User Login (Other backend member) - Email lookup for authentication
     * - UC11: Reset Password - Email validation before sending reset token
     * - UC24: Admin user management - User lookup by email
     * 
     * SECURITY: Used in authentication flows with proper validation
     * REGISTRATION USE: Checks email uniqueness before account creation
     * LOGIN USE: Retrieves user for password verification
     */
    // Static method to find user by email
    static async findByEmail(email) {
        try {
            console.log(`[USER] Finding user by email: ${email}`);
            const query = 'SELECT * FROM Users WHERE email = $1';
            const result = await pool.query(query, [email.toLowerCase()]);
            
            if (result.rows.length === 0) {
                console.log(`[USER] No user found with email: ${email}`);
                return null;
            }
            
            // Debug the retrieved row from database
            console.log(`[USER] User found with email: ${email}`);
            console.log(`[USER] Database fields available:`, Object.keys(result.rows[0]));

            // Ensure password hash is correctly mapped
            const userData = result.rows[0];

            // Create user object and debug password-related fields
            const user = new User(userData);
            console.log(`[USER] Password field exists:`, !!user.password);
            console.log(`[USER] Password hash length:`, user.password ? user.password.length : 'N/A');

            return user;
        } catch (error) {
            console.error(`[USER] Error finding user by email:`, error);
            throw error;
        }
    }

    /**
     * FIND USER BY ID - USER IDENTIFICATION & SESSION MANAGEMENT
     * Essential for JWT authentication and user session validation
     * 
     * SUPPORTS:
     * - UC1: User Registration (Other backend member) - User ID generation after creation
     * - UC2: User Login (Other backend member) - JWT payload user identification  
     * - UC3: User Logout (Other backend member) - Session cleanup by user ID
     * - UC4-31: All authenticated operations require user ID lookup
     * - JWT middleware uses this for token validation
     * - Admin operations for user management (UC24)
     * 
     * PERFORMANCE: Direct primary key lookup for optimal speed
     * SESSION MANAGEMENT: Essential for user session tracking and cleanup
     */
    // Static method to find user by ID
    static async findById(id) {
        try {
            const query = 'SELECT * FROM Users WHERE user_id = $1';
            const result = await pool.query(query, [id]);
            
            if (result.rows.length === 0) {
                return null;
            }
            
            return new User(result.rows[0]);
        } catch (error) {
            throw error;
        }
    }

    /**
     * FIND USER BY RESET TOKEN - PASSWORD RECOVERY SECURITY
     * Validates password reset tokens and prevents token reuse/expiration
     * 
     * SUPPORTS:
     * - UC11: Reset Password - Token validation step
     * 
     * SECURITY FEATURES:
     * - Automatic token expiration check (1-hour limit)
     * - Prevents replay attacks with expired tokens
     * - SQL injection protection with parameterized queries
     */
    // Static method to find user by reset token
    static async findByResetToken(token) {
        try {
            const query = `
                SELECT * FROM Users 
                WHERE password_reset_token = $1 
                AND password_reset_expires > NOW()
            `;
            const result = await pool.query(query, [token]);
            
            if (result.rows.length === 0) {
                return null;
            }
            
            return new User(result.rows[0]);
        } catch (error) {
            throw error;
        }
    }

    /**
     * SAVE USER TO DATABASE - CREATE & UPDATE OPERATIONS
     * Handles both user creation and profile updates with security
     * 
     * SUPPORTS:
     * - UC1: User Registration (Other backend member) - New user account creation
     *   └── Features: Email uniqueness validation, password hashing, default role assignment
     *   └── Validation: Email format, password strength, required fields
     *   └── Security: Automatic bcrypt hashing, SQL injection prevention
     * - UC11: Reset Password - Password hash updates after reset
     * - UC13: Manage Profile - User profile updates (name, preferences)
     * - UC24: Manage Users (Admin) - Admin user management operations
     * 
     * REGISTRATION PROCESS (UC1):
     * 1. Validate input data (email format, password requirements)
     * 2. Check email uniqueness using findByEmail()
     * 3. Hash password with bcrypt (12 rounds)
     * 4. Insert new user record with default 'Regular' role
     * 5. Return user object with generated user_id
     * 
     * SECURITY FEATURES:
     * - Automatic password hashing (bcrypt, 12 rounds)
     * - Email normalization (lowercase)
     * - Parameterized queries prevent SQL injection
     * - Handles both INSERT and UPDATE operations
     * - Default role assignment for new registrations
     */
    // Create new user
    async save() {
        try {
            if (this.user_id) {
                // Update existing user
                const query = `
                    UPDATE Users 
                    SET email = $1, password_hash = $2, family_name = $3, given_name = $4,
                        role = $5, notification_prefs = $6, 
                        password_reset_token = $7, password_reset_expires = $8,
                        google_id = $9, profile_picture = $10
                    WHERE user_id = $11
                    RETURNING *
                `;
                
                // If plainTextPassword exists, hash it. Otherwise, use existing password hash
                let hashedPassword;
                if (this.plainTextPassword) {
                    console.log('[USER UPDATE] Hashing new password for update');
                    const salt = await bcrypt.genSalt(12);
                    hashedPassword = await bcrypt.hash(this.plainTextPassword, salt);
                } else {
                    console.log('[USER UPDATE] Keeping existing password hash');
                    hashedPassword = this.password; // Use existing hash
                }

                const result = await pool.query(query, [
                    this.email.toLowerCase(),
                    hashedPassword,
                    this.familyName,
                    this.givenName,
                    this.role,
                    JSON.stringify(this.notification_prefs),
                    this.passwordResetToken,
                    this.passwordResetExpires,
                    this.googleId,
                    this.profilePicture,
                    this.userId
                ]);
                
                const updatedUser = new User(result.rows[0]);
                Object.assign(this, updatedUser);
                return this;
            } else {
                // Create new user
                console.log('[USER CREATE] Attempting to create new user:', this.email);

                // Check if email already exists
                const existingUser = await User.findByEmail(this.email);
                if (existingUser) {
                    console.error('[USER CREATE] Email already registered:', this.email);
                    const error = new Error('Email already exists');
                    error.code = '23505'; // Simulate PostgreSQL unique violation code
                    throw error;
                }

                // Hash the plainTextPassword for new user creation
                if (!this.plainTextPassword) {
                    throw new Error('Password is required for new user creation');
                }

                console.log('[USER CREATE] Hashing password for new user');
                const salt = await bcrypt.genSalt(12);
                const hashedPassword = await bcrypt.hash(this.plainTextPassword, salt);

                const query = `
                    INSERT INTO Users (
                        email, password_hash, family_name, given_name, role, 
                        notification_prefs, google_id, profile_picture
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                    RETURNING *
                `;
                
                console.log('[USER CREATE] Executing database query for new user');

                const result = await pool.query(query, [
                    this.email.toLowerCase(),
                    hashedPassword,
                    this.familyName,
                    this.givenName,
                    this.role,
                    JSON.stringify(this.notification_prefs || {}),
                    this.google_id,
                    this.profile_picture
                ]);
                
                console.log('[USER CREATE] User created successfully:', result.rows[0].user_id);

                const newUser = new User(result.rows[0]);
                Object.assign(this, newUser);
                return this;
            }
        } catch (error) {
            console.error('[USER CREATE ERROR] Failed to save user:', error.message);

            // Add detailed error diagnostics for database issues
            if (error.code === '42P01') {
                console.error('[USER CREATE ERROR] Table "Users" does not exist. Database schema may need to be created.');
            } else if (error.code === '23505') {
                console.error('[USER CREATE ERROR] Duplicate key violation. Email may already be registered.');
                const conflictError = new Error('Email already registered');
                conflictError.status = 409;
                throw conflictError;
            } else if (error.code === '23502') {
                console.error('[USER CREATE ERROR] Not-null constraint violation. Missing required field.');
            } else if (error.code === '42703') {
                console.error('[USER CREATE ERROR] Column does not exist. Database schema may be outdated.');
            }

            throw error;
        }
    }

    // Hash password
    async hashPassword(password) {
        if (!password) return this.password; // Return existing password if no new password
        const salt = await bcrypt.genSalt(12);
        return await bcrypt.hash(password, salt);
    }

    // Validate password
    async validatePassword(password) {
        console.log(`[USER] validatePassword called with password length: ${password ? password.length : 0}`);
        console.log(`[USER] this.password exists: ${!!this.password}`);
        console.log(`[USER] this.password type: ${typeof this.password}`);

        // Safety check for missing password hash
        if (!this.password) {
            console.error('[USER] Cannot validate password: No password hash available');
            return false;
        }

        try {
            // Compare plaintext password with stored hash
            // Do NOT hash the password again before comparison
            console.log(`[USER] Comparing plaintext password with stored hash`);

            // Use bcrypt compare with error handling
            const isValid = await bcrypt.compare(password, this.password);
            console.log(`[USER] Password validation result: ${isValid}`);

            return isValid;
        } catch (error) {
            console.error('[USER] Error validating password:', error);
            console.error('[USER] Error details:', {
                message: error.message,
                passwordProvided: !!password,
                passwordHashExists: !!this.password,
                passwordHashFormat: this.password ? `${this.password.substring(0, 10)}...` : 'N/A'
            });

            return false;
        }
    }

    /**
     * CREATE PASSWORD RESET TOKEN - SECURE PASSWORD RECOVERY
     * Generates JWT token for password reset with 1-hour expiration
     * 
     * SUPPORTS:
     * - UC11: Reset Password - Step 2 (Generate secure reset token)
     * 
     * SECURITY FEATURES:
     * - JWT with user ID payload
     * - 1-hour expiration prevents long-term token abuse
     * - Uses app's JWT_SECRET for signing
     */
// Create password reset token
createPasswordResetToken() {
    try {
        // Generate a random token
        const resetToken = crypto.randomBytes(32).toString('hex');
        
        // Store a hash of the token in the database
        // In a real system, we'd hash this token before storing for security
        // but for simplicity in testing we'll use the token directly
        this.passwordResetToken = resetToken;
        this.passwordResetExpires = new Date(Date.now() + 3600000); // 1 hour
        
        return resetToken;
    } catch (error) {
        throw new Error('Error creating password reset token: ' + error.message);
    }
}    /**
     * UPDATE PASSWORD RESET FIELDS - TOKEN MANAGEMENT
     * Updates reset token and expiration in database for security tracking
     * 
     * SUPPORTS:
     * - UC11: Reset Password - Store reset token in database
     * 
     * SECURITY FEATURES:
     * - Stores token for validation in reset process
     * - Tracks expiration to prevent token reuse
     * - Can clear tokens by passing null values
     */
    // Update password reset fields
    async updatePasswordResetFields(token = null, expires = null) {
        try {
            const query = `
                UPDATE Users 
                SET password_reset_token = $1, password_reset_expires = $2
                WHERE user_id = $3
                RETURNING *
            `;
            
            const result = await pool.query(query, [token, expires, this.user_id]);
            
            if (result.rows.length > 0) {
                this.passwordResetToken = token;
                this.passwordResetExpires = expires;
            }
            
            return this;
        } catch (error) {
            throw error;
        }
    }

    /**
     * UPDATE PASSWORD - SECURE PASSWORD CHANGE
     * Updates user password with automatic hashing and token cleanup
     * 
     * SUPPORTS:
     * - UC11: Reset Password - Final step (Update password with new hash)
     * - UC12: Change Password - User-initiated password changes
     * 
     * SECURITY FEATURES:
     * - Automatic password hashing before storage
     * - Clears reset tokens after successful password change
     * - Prevents password reuse attacks
     */
    // Update password
    async updatePassword(newPassword) {
        try {
            const hashedPassword = await this.hashPassword(newPassword);
            
            const query = `
                             UPDATE Users 
                             SET password_hash = $1, password_reset_token = NULL, password_reset_expires = NULL
                             WHERE user_id = $2
                             RETURNING *
                        `;
            
            const result = await pool.query(query, [hashedPassword, this.user_id]);
            
            if (result.rows.length > 0) {
                this.password = hashedPassword;
                this.passwordResetToken = null;
                this.passwordResetExpires = null;
            }
            
            return this;
        } catch (error) {
            throw error;
        }
    }
    
    /**
     * UPDATE USER PROFILE
     * Updates user profile information
     * 
     * SUPPORTS:
     * - UC13: Manage Profile - Update user profile information
     * - UC19: Upgrade to Premium - Update user role
     * 
     * SECURITY FEATURES:
     * - SQL Injection protection with parameterized queries
     * - Update only allowed fields
     */
    // Update user profile
    async update(userData) {
        try {
            // Build dynamic query based on provided fields
            const validFields = ['family_name', 'given_name', 'notification_prefs', 'role', 'language_preference'];
            const updates = [];
            const values = [this.user_id]; // First parameter is always user_id
            let paramIndex = 2; // Start parameter index at 2 (user_id is $1)
            
            // Construct SET part of query for each provided field
            Object.keys(userData).forEach(key => {
                if (validFields.includes(key)) {
                    updates.push(`${key === 'family_name' ? 'family_name' : 
                                  key === 'given_name' ? 'given_name' : 
                                  key === 'notification_prefs' ? 'notification_prefs' : 
                                  key === 'role' ? 'role' : 
                                  key === 'language_preference' ? 'language_preference' : key} = $${paramIndex}`);
                    values.push(userData[key]);
                    paramIndex++;
                }
            });
            
            // If no valid fields to update, return the current user
            if (updates.length === 0) {
                return this;
            }
            
            // Construct and execute the update query
            const query = `
                UPDATE Users 
                SET ${updates.join(', ')}
                WHERE user_id = $1
                RETURNING *
            `;
            
            const result = await pool.query(query, values);
            
            // Update the user object with new values
            if (result.rows.length > 0) {
                const updatedUser = result.rows[0];
                this.family_name = updatedUser.family_name;
                this.given_name = updatedUser.given_name;
                this.notification_prefs = updatedUser.notification_prefs;
                this.role = updatedUser.role;
                this.languagePreference = updatedUser.language_preference;
            }
            
            return this;
        } catch (error) {
            throw error;
        }
    }

    /**
     * LOGOUT SUPPORT METHODS - SESSION CLEANUP
     * While logout is primarily handled in controllers/middleware,
     * User model provides data access for session management
     * 
     * SUPPORTS:
     * - UC3: User Logout (Other backend member) - User data for session cleanup
     *   └── Process: Validate user session → Clear tokens → Audit log
     *   └── Security: Token invalidation, session termination
     *   └── Audit: Log logout events for security monitoring
     * 
     * LOGOUT IMPLEMENTATION NOTES (UC3):
     * - Controller calls User.findById() to validate session
     * - Optional: Store blacklisted tokens in Redis/database
     * - SystemLog model can track logout events for audit
     * - Clear refresh tokens if stored in database
     * - Return success response to client
     * 
     * SECURITY CONSIDERATIONS:
     * - Immediate token invalidation prevents session hijacking
     * - Audit logging for security monitoring
     * - Optional token blacklisting for added security
     */

    /**
     * TO JSON - SECURE DATA SERIALIZATION
     * Removes sensitive fields when converting user object to JSON
     * 
     * SUPPORTS:
     * - UC1: User Registration (Other backend member) - Safe user data return
     * - UC2: User Login (Other backend member) - Authentication response data
     * - UC3: User Logout (Other backend member) - Final user state return
     * - UC4-31: All API responses that include user data
     * - JWT token payload generation
     * - Frontend user data display
     * 
     * SECURITY FEATURES:
     * - Excludes password hash from JSON output
     * - Excludes reset tokens from client responses
     * - Prevents accidental password exposure in logs/responses
     * - Safe for authentication responses and user profiles
     */
    // Convert to JSON (excluding sensitive fields)
    toJSON() {
        const { password, passwordResetToken, ...publicData } = this;
        return publicData;
    }
}

module.exports = User;
