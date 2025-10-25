require('dotenv').config();

// Mock dependencies first
jest.mock('jsonwebtoken', () => ({
    sign: jest.fn().mockReturnValue('mock.jwt.token'),
    verify: jest.fn().mockReturnValue({ id: '123' })
}));
jest.mock('nodemailer', () => ({
    createTransport: jest.fn().mockReturnValue({
        sendMail: jest.fn().mockImplementation((mailOptions) => {
            console.log('[TEST] Email would be sent to:', mailOptions.to);
            return Promise.resolve({ messageId: 'test-email-id-' + Date.now() });
        })
    })
}));
jest.mock('bcryptjs', () => ({
    compare: jest.fn().mockResolvedValue(true),
    hash: jest.fn().mockResolvedValue('hashedPassword')
}));

// Mock data
const { mockUsers } = require('./mocks/mockData');

// Set up User mock
const mockUserPrototype = {
    save: jest.fn().mockResolvedValue({ 
        user_id: '123', 
        email: 'sonicprime1963@gmail.com',
        family_name: 'Doe',
        given_name: 'John',
        role: 'Regular'
    }),
    validatePassword: jest.fn().mockResolvedValue(true),
    updatePassword: jest.fn().mockResolvedValue(true)
};

class MockUser {
    constructor(data) {
        Object.assign(this, data);
        Object.assign(this, mockUserPrototype);
    }

    static findByEmail = jest.fn(email => Promise.resolve(mockUsers.find(u => u.email === email)));
    static findById = jest.fn(id => Promise.resolve(mockUsers.find(u => u.user_id === id)));
    static findByResetToken = jest.fn();
}

jest.mock('../src/models', () => ({
    User: MockUser,
    SystemLog: {
        info: jest.fn(),
        error: jest.fn()
    }
}));

// Mock email service
jest.mock('../src/services/emailService', () => ({
    verifyConnection: jest.fn().mockResolvedValue(true),
    sendEmail: jest.fn().mockImplementation(async (mailOptions) => {
        // Log email details for debugging
        console.log('[TEST] Email would be sent to:', mailOptions.to);
        return { messageId: 'test-email-id-' + Date.now() };
    })
}));

// Import dependencies after mocks
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');
const { User, SystemLog } = require('../src/models');
const emailService = require('../src/services/emailService');
const authController = require('../src/controller/authController');

describe('Authentication Controller Tests', () => {
  // Global setup
  beforeAll(() => {
    // Set default values for required environment variables if not present
    process.env = {
      ...process.env,
      JWT_SECRET: process.env.JWT_SECRET || 'test-jwt-secret-key',
      EMAIL_USER: process.env.EMAIL_USER || 'sonicprime1963@gmail.com',
      EMAIL_PASS: process.env.EMAIL_PASS || 'test-password',
      EMAIL_PASSWORD: process.env.EMAIL_PASSWORD || 'test-password', // Add EMAIL_PASSWORD for emailService.js
      EMAIL_HOST: process.env.EMAIL_HOST || 'smtp.gmail.com',
      EMAIL_PORT: process.env.EMAIL_PORT || '465',
      EMAIL_SERVICE: process.env.EMAIL_SERVICE || 'gmail',
      EMAIL_USE_SERVICE: process.env.EMAIL_USE_SERVICE || 'true',
      EMAIL_SECURE: process.env.EMAIL_SECURE || 'true',
      FRONTEND_URL: process.env.FRONTEND_URL || 'http://localhost:3000'
    };

    // Log test configuration (masking sensitive data)
    console.log('Test environment configuration:', {
      EMAIL_USER: process.env.EMAIL_USER,
      EMAIL_HOST: process.env.EMAIL_HOST,
      EMAIL_PORT: process.env.EMAIL_PORT,
      EMAIL_SERVICE: process.env.EMAIL_SERVICE,
      EMAIL_USE_SERVICE: process.env.EMAIL_USE_SERVICE,
      EMAIL_SECURE: process.env.EMAIL_SECURE,
      FRONTEND_URL: process.env.FRONTEND_URL,
      // Mask sensitive data
      EMAIL_PASS: '****',
      JWT_SECRET: '****'
    });
  });

  // Reset mocks before each test
  beforeEach(() => {
    jest.clearAllMocks();
  });

  // Cleanup after all tests
  afterAll(() => {
    jest.restoreAllMocks();
  });

  //describe('createTransporter()', () => {
    // Since createTransporter is an internal function, we'll test it through the functions that use it
  //});

  //describe('generateToken()', () => {
    // Since generateToken is an internal function, we'll test it through the functions that use it
  //});

  describe('forgotPassword()', () => {
    let req, res;

    beforeEach(() => {
      req = {
        body: {
          email: 'sonicprime1963@gmail.com'
        }
      };
      res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      };
    });

    it('[FP_01] should successfully send reset password email', async () => {
      // Arrange
      const mockUser = {
        email: 'sonicprime1963@gmail.com',
        family_name: 'Doe',
        createPasswordResetToken: jest.fn().mockReturnValue('reset-token-123'),
        updatePasswordResetFields: jest.fn().mockResolvedValue(true)
      };
      User.findByEmail.mockResolvedValue(mockUser);
      emailService.verifyConnection.mockResolvedValue(true);
      emailService.sendEmail.mockResolvedValue({ messageId: 'test-id' });

      // Act
      await authController.forgotPassword(req, res);

      // Assert
      expect(User.findByEmail).toHaveBeenCalledWith('sonicprime1963@gmail.com');
      expect(emailService.sendEmail).toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith({
        success: true,
        message: 'Password reset email sent successfully',
        data: {
          email: 'sonicprime1963@gmail.com',
          expiresIn: '1 hour'
        }
      });
    });

    it('[FP_02] should return 400 for missing email', async () => {
      // Arrange
      req.body.email = undefined;

      // Act
      await authController.forgotPassword(req, res);

      // Assert
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        success: false,
        message: 'Email is required'
      });
    });

    it('[FP_03] should return 400 for invalid email format', async () => {
      // Arrange
      req.body.email = 'invalid-email';

      // Act
      await authController.forgotPassword(req, res);

      // Assert
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        success: false,
        message: 'Please provide a valid email address'
      });
    });

    it('[FP_04] should return 404 for non-existent user', async () => {
      // Arrange
      User.findByEmail.mockResolvedValue(null);

      // Act
      await authController.forgotPassword(req, res);

      // Assert
      expect(res.status).toHaveBeenCalledWith(404);
      expect(res.json).toHaveBeenCalledWith({
        success: false,
        message: 'No account found with this email address. Please check the email or register first.'
      });
    });

    it('[FP_05] should handle email service connection failure', async () => {
      // Arrange
      const mockUser = {
        email: 'sonicprime1963@gmail.com',
        createPasswordResetToken: jest.fn().mockReturnValue('reset-token-123'),
        updatePasswordResetFields: jest.fn().mockResolvedValue(true)
      };
      User.findByEmail.mockResolvedValue(mockUser);
      emailService.verifyConnection.mockResolvedValue(false);

      // Act
      await authController.forgotPassword(req, res);

      // Assert
      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith({
        success: false,
        message: 'Failed to send password reset email. Please try again later or contact support.'
      });
    });

    it('[FP_06] should handle database errors', async () => {
      // Arrange
      User.findByEmail.mockRejectedValue(new Error('Database connection error'));

      // Act
      await authController.forgotPassword(req, res);

      // Assert
      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith({
        success: false,
        message: 'An error occurred during the password reset process'
      });
      expect(SystemLog.error).toHaveBeenCalled();
    });
  });

  describe('resetPassword()', () => {
    let req, res;

    beforeEach(() => {
      req = {
        query: { token: 'valid-token-123' },
        body: {
          password: 'newPassword123',
          confirmPassword: 'newPassword123'
        }
      };
      res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      };
    });

    it('[RP_01] should successfully reset password', async () => {
      // Arrange
      const mockUser = {
        user_id: '123',
        email: 'sonicprime1963@gmail.com',
        family_name: 'Doe',
        updatePassword: jest.fn().mockResolvedValue(true)
      };
      jwt.verify.mockReturnValue({ id: '123' });
      User.findByResetToken.mockResolvedValue(mockUser);

      // Act
      await authController.resetPassword(req, res);

      // Assert
      expect(jwt.verify).toHaveBeenCalled();
      expect(User.findByResetToken).toHaveBeenCalledWith('valid-token-123');
      expect(mockUser.updatePassword).toHaveBeenCalledWith('newPassword123');
      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith({
        message: 'Password reset successful. You can now login with your new password.'
      });
    });

    it('[RP_02] should return 400 for missing token', async () => {
      // Arrange
      req.query.token = undefined;

      // Act
      await authController.resetPassword(req, res);

      // Assert
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        error: 'Reset token is required'
      });
    });

    it('[RP_03] should return 400 for missing password fields', async () => {
      // Arrange
      req.body = {};

      // Act
      await authController.resetPassword(req, res);

      // Assert
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        error: 'Password and confirm password are required'
      });
    });

    it('[RP_04] should return 400 for mismatched passwords', async () => {
      // Arrange
      req.body.confirmPassword = 'differentPassword';

      // Act
      await authController.resetPassword(req, res);

      // Assert
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        error: 'Passwords do not match'
      });
    });

    it('[RP_05] should return 400 for short password', async () => {
      // Arrange
      req.body.password = req.body.confirmPassword = '12345';

      // Act
      await authController.resetPassword(req, res);

      // Assert
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        error: 'Password must be at least 6 characters long'
      });
    });

    it('[RP_06] should return 401 for invalid token', async () => {
      // Arrange
      jwt.verify.mockImplementation(() => {
        throw new Error('Invalid token');
      });

      // Act
      await authController.resetPassword(req, res);

      // Assert
      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({
        error: 'Invalid or expired password reset token'
      });
    });
  });

  describe('changePassword()', () => {
    let req, res;

    beforeEach(() => {
      req = {
        user: { user_id: '123' },
        body: {
          currentPassword: 'oldPass123',
          newPassword: 'newPass123',
          confirmPassword: 'newPass123'
        }
      };
      res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      };
    });

    it('[CP_01] should successfully change password', async () => {
      // Arrange
      const mockUser = {
        user_id: '123',
        password: 'hashedOldPass',
        validatePassword: jest.fn().mockResolvedValue(true),
        updatePassword: jest.fn().mockResolvedValue(true)
      };
      User.findById.mockResolvedValue(mockUser);
      bcrypt.compare.mockResolvedValue(true);

      // Act
      await authController.changePassword(req, res);

      // Assert
      expect(User.findById).toHaveBeenCalledWith('123');
      expect(bcrypt.compare).toHaveBeenCalledWith('oldPass123', 'hashedOldPass');
      expect(mockUser.updatePassword).toHaveBeenCalledWith('newPass123');
      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith({
        success: true,
        message: 'Password changed successfully'
      });
    });

    it('[CP_02] should return 400 for missing required fields', async () => {
      // Arrange
      req.body = {};

      // Act
      await authController.changePassword(req, res);

      // Assert
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        error: 'Current password, new password, and password confirmation are required'
      });
    });

    it('[CP_03] should return 400 when passwords do not match', async () => {
      // Arrange
      req.body.confirmPassword = 'differentPass123';

      // Act
      await authController.changePassword(req, res);

      // Assert
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        error: 'New password and confirmation password do not match'
      });
    });

    it('[CP_04] should return 404 when user not found', async () => {
      // Arrange
      User.findById.mockResolvedValue(null);

      // Act
      await authController.changePassword(req, res);

      // Assert
      expect(res.status).toHaveBeenCalledWith(404);
      expect(res.json).toHaveBeenCalledWith({
        error: 'User not found'
      });
    });

    it('[CP_05] should return 401 for incorrect current password', async () => {
      // Arrange
      const mockUser = {
        user_id: '123',
        password: 'hashedOldPass'
      };
      User.findById.mockResolvedValue(mockUser);
      bcrypt.compare.mockResolvedValue(false);

      // Act
      await authController.changePassword(req, res);

      // Assert
      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({
        error: 'Current password is incorrect'
      });
    });

    it('[CP_06] should return 400 for weak password', async () => {
      // Arrange
      User.findById.mockResolvedValue({
        user_id: '123',
        password: 'hashedOldPass',
        validatePassword: jest.fn().mockResolvedValue(true)
      });
      bcrypt.compare.mockResolvedValue(true);
      req.body.newPassword = req.body.confirmPassword = '123';

      // Act
      await authController.changePassword(req, res);

      // Assert
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        error: 'New password must be at least 8 characters long'
      });
    });
  });

  describe('register()', () => {
    let req, res;

    beforeEach(() => {
      req = {
        body: {
          email: 'sonicprime1963@gmail.com',
          password: 'Password123',
          familyName: 'Doe',
          givenName: 'John'
        }
      };
      res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      };
    });

    it('[REG_01] should successfully register new user', async () => {
      // Arrange
      const mockSavedUser = {
        user_id: '123',
        email: 'sonicprime1963@gmail.com',
        family_name: 'Doe',
        given_name: 'John',
        role: 'Regular'
      };
      User.findByEmail.mockResolvedValue(null);
      const mockToken = 'mock.jwt.token';
      jwt.sign.mockReturnValue(mockToken);

      mockUserPrototype.save.mockResolvedValueOnce(mockSavedUser);

      // Act
      await authController.register(req, res);

      // Assert
      expect(res.status).toHaveBeenCalledWith(201);
      const response = res.json.mock.calls[0][0];
      expect(response.success).toBe(true);
      expect(response.message).toBe('Registration successful');
      expect(response.data.user).toEqual({
        user_id: '123',
        email: 'sonicprime1963@gmail.com',
        family_name: 'Doe',
        given_name: 'John',
        role: 'Regular'
      });
      // Verify token exists but don't check exact value
      expect(typeof response.data.token).toBe('string');
      expect(response.data.token.length).toBeGreaterThan(0);
    });

    it('[REG_02] should return 409 for existing email', async () => {
      // Arrange
      User.findByEmail.mockResolvedValue({ email: 'sonicprime1963@gmail.com' });

      // Act
      await authController.register(req, res);

      // Assert
      expect(res.status).toHaveBeenCalledWith(409);
      expect(res.json).toHaveBeenCalledWith({
        success: false,
        message: 'Email already registered'
      });
    });

    it('[REG_03] should handle database errors gracefully', async () => {
      // Arrange
      User.findByEmail.mockResolvedValue(null);
      mockUserPrototype.save.mockRejectedValueOnce(new Error('Database connection failed'));

      // Act
      await authController.register(req, res);

      // Assert
      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith({
        success: false,
        message: 'Registration failed. Please try again later.'
      });
    });
  });

  describe('login()', () => {
    let req, res;

    beforeEach(() => {
      req = {
        body: {
          email: 'user@test.com',
          password: 'Password123'
        }
      };
      res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      };
    });

    it('[LOGIN_01] should successfully authenticate user', async () => {
      // Arrange
      const mockUser = {
        user_id: '123',
        email: 'user@test.com',
        familyName: 'Doe',
        givenName: 'John',
        role: 'Regular',
        validatePassword: jest.fn().mockResolvedValue(true)
      };
      User.findByEmail.mockResolvedValue(mockUser);
      const mockToken = 'mock.jwt.token';
      jwt.sign.mockReturnValue(mockToken);

      // Act
      await authController.login(req, res);

      // Assert
      expect(res.status).toHaveBeenCalledWith(200);
      const response = res.json.mock.calls[0][0];
      expect(response.success).toBe(true);
      expect(response.message).toBe('Login successful');
      expect(response.data.user).toEqual({
        user_id: '123',
        email: 'user@test.com',
        family_name: 'Doe',
        given_name: 'John',
        full_name: 'John Doe',
        role: 'Regular'
      });
      // Verify token exists but don't check exact value
      expect(typeof response.data.token).toBe('string');
      expect(response.data.token.length).toBeGreaterThan(0);
    });

    it('[LOGIN_02] should return 400 for missing credentials', async () => {
      // Arrange
      req.body = {};

      // Act
      await authController.login(req, res);

      // Assert
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        error: 'Email and password are required'
      });
    });

    it('[LOGIN_03] should return 401 for invalid credentials', async () => {
      // Arrange
      const mockUser = {
        validatePassword: jest.fn().mockResolvedValue(false)
      };
      User.findByEmail.mockResolvedValue(mockUser);

      // Act
      await authController.login(req, res);

      // Assert
      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({
        error: 'Invalid email or password'
      });
    });

    it('[LOGIN_04] should return 401 for non-existent user', async () => {
      // Arrange
      User.findByEmail.mockResolvedValue(null);

      // Act
      await authController.login(req, res);

      // Assert
      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({
        error: 'Invalid email or password'
      });
    });
  });

  describe('logout()', () => {
    let req, res;

    beforeEach(() => {
      req = {
        user: { user_id: '123' }
      };
      res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      };
    });

    it('[LOGOUT_01] should successfully log out user', async () => {
      // Act
      await authController.logout(req, res);

      // Assert
      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith({
        success: true,
        message: 'Logout successful'
      });
    });

    it('[LOGOUT_02] should handle logout without user context', async () => {
      // Arrange
      req.user = null;

      // Act
      await authController.logout(req, res);

      // Assert
      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith({
        success: true,
        message: 'Logout successful'
      });
    });

    it('[LOGOUT_03] should handle errors during logout', async () => {
      // Arrange
      const error = new Error('Logout processing error');
      console.error = jest.fn(); // Mock console.error
      
      // Force an error by making user_id a getter that throws
      Object.defineProperty(req.user, 'user_id', {
        get: function() {
          throw error;
        }
      });

      // Act
      await authController.logout(req, res);

      // Assert
      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith({
        error: 'Logout failed. Please try again later.'
      });
      expect(console.error).toHaveBeenCalledWith('Logout error:', error);
    });
  });
});
