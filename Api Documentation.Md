# API Routes Documentation

## Base URL
```
http://localhost:5000/api
```

## Table of Contents
- [Authentication Routes](#authentication-routes)
- [OAuth Routes](#oauth-routes)
- [Response Format](#response-format)
- [Error Codes](#error-codes)

---

## Authentication Routes

### Public Routes

#### 1. Register User
```http
POST /api/auth/register
```

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "firstName": "John",
  "lastName": "Doe",
  "displayName": "John Doe",
  "phone": "+1234567890",
  "location": "New York, USA"
}
```

**Response:**
```json
{
  "success": true,
  "message": "User registered successfully. Please check your email to verify your account.",
  "data": {
    "user": {
      "id": "uuid",
      "email": "user@example.com",
      "firstName": "John",
      "lastName": "Doe",
      "displayName": "John Doe",
      "role": "USER",
      "isActive": true,
      "emailVerified": false,
      "createdAt": "2025-02-02T00:00:00.000Z"
    },
    "token": "jwt_token_here"
  },
  "requiresVerification": true
}
```

#### 2. Login
```http
POST /api/auth/login
```

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123!"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "user": {
      "id": "uuid",
      "email": "user@example.com",
      "firstName": "John",
      "lastName": "Doe",
      "displayName": "John Doe",
      "role": "USER",
      "isVendor": false,
      "isBuyer": true,
      "isSponsor": false,
      "emailVerified": true,
      "isActive": true,
      "avatarUrl": null,
      "phone": "+1234567890",
      "location": "New York, USA",
      "lastLogin": "2025-02-02T00:00:00.000Z",
      "createdAt": "2025-01-01T00:00:00.000Z",
      "vendorProfile": null
    },
    "token": "jwt_token_here"
  }
}
```

#### 3. Verify Email
```http
GET /api/auth/verify-email?token=verification_token_here
```

**Response:**
```json
{
  "success": true,
  "message": "Email verified successfully!",
  "data": {
    "user": {
      "id": "uuid",
      "email": "user@example.com",
      "firstName": "John",
      "lastName": "Doe",
      "emailVerified": true,
      "role": "USER",
      "createdAt": "2025-01-01T00:00:00.000Z"
    }
  }
}
```

#### 4. Resend Verification Email
```http
POST /api/auth/resend-verification
```

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

**Response:**
```json
{
  "success": true,
  "message": "If an account exists with this email, a verification link has been sent."
}
```

#### 5. Request Password Reset
```http
POST /api/auth/request-password-reset
```

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

**Response:**
```json
{
  "success": true,
  "message": "If the email exists, a reset link has been sent"
}
```

#### 6. Reset Password
```http
POST /api/auth/reset-password
```

**Request Body:**
```json
{
  "token": "reset_token_here",
  "newPassword": "NewSecurePass123!"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Password reset successfully"
}
```

#### 7. Check Account Status
```http
POST /api/auth/check-account-status
```

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "exists": true,
    "active": true,
    "deactivated": false,
    "deactivatedAt": null,
    "deactivationType": null,
    "deactivatedByAdmin": false,
    "adminDetails": null,
    "emailVerified": true,
    "lastLogin": "2025-02-02T00:00:00.000Z",
    "canBeReactivated": false,
    "message": "Account is active"
  }
}
```

#### 8. Request Reactivation
```http
POST /api/auth/request-reactivation
```

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

**Response:**
```json
{
  "success": true,
  "message": "If a deactivated account exists with this email, a reactivation link has been sent.",
  "data": {
    "emailSent": true,
    "expiresAt": "2025-02-03T00:00:00.000Z"
  }
}
```

#### 9. Complete Reactivation
```http
POST /api/auth/complete-reactivation
```

**Request Body:**
```json
{
  "token": "reactivation_token_here",
  "newPassword": "NewSecurePass123!"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Account reactivated successfully. You can now login with your new password.",
  "data": {
    "email": "user@example.com",
    "reactivatedAt": "2025-02-02T00:00:00.000Z"
  }
}
```

---

### Protected Routes
**Authentication Required:** All protected routes require a valid JWT token in the Authorization header or cookie.

**Header:**
```
Authorization: Bearer <jwt_token>
```

#### 10. Logout
```http
POST /api/auth/logout
```

**Response:**
```json
{
  "success": true,
  "message": "Logged out successfully"
}
```

#### 11. Get Current User
```http
GET /api/auth/me
```

**Response:**
```json
{
  "success": true,
  "data": {
    "user": {
      "id": "uuid",
      "email": "user@example.com",
      "firstName": "John",
      "lastName": "Doe",
      "displayName": "John Doe",
      "role": "USER",
      "isVendor": false,
      "isBuyer": true,
      "isSponsor": false,
      "emailVerified": true,
      "isActive": true,
      "avatarUrl": null,
      "bio": null,
      "website": null,
      "location": "New York, USA",
      "phone": "+1234567890",
      "lastLogin": "2025-02-02T00:00:00.000Z",
      "createdAt": "2025-01-01T00:00:00.000Z",
      "updatedAt": "2025-02-02T00:00:00.000Z",
      "vendorProfile": null
    }
  }
}
```

#### 12. Check User Status
```http
GET /api/auth/status
```

**Response:**
```json
{
  "success": true,
  "data": {
    "user": {
      "id": "uuid",
      "email": "user@example.com",
      "firstName": "John",
      "lastName": "Doe",
      "displayName": "John Doe",
      "role": "USER",
      "isActive": true,
      "emailVerified": true,
      "isVendor": false,
      "isBuyer": true,
      "isSponsor": false,
      "avatarUrl": null,
      "phone": "+1234567890",
      "location": "New York, USA",
      "lastLogin": "2025-02-02T00:00:00.000Z",
      "createdAt": "2025-01-01T00:00:00.000Z",
      "updatedAt": "2025-02-02T00:00:00.000Z",
      "preferences": {}
    },
    "needsTokenRefresh": false,
    "isActive": true,
    "status": "active",
    "deactivatedAt": null,
    "deactivationType": null,
    "message": "Account is active"
  }
}
```

#### 13. Change Password
```http
POST /api/auth/change-password
```

**Request Body:**
```json
{
  "currentPassword": "OldPassword123!",
  "newPassword": "NewSecurePass123!"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Password updated successfully"
}
```

#### 14. Update Profile
```http
PUT /api/auth/profile
```

**Request Body:**
```json
{
  "firstName": "John",
  "lastName": "Doe",
  "displayName": "John Doe",
  "avatarUrl": "https://example.com/avatar.jpg",
  "bio": "Software Developer",
  "website": "https://johndoe.com",
  "location": "San Francisco, CA",
  "phone": "+1234567890",
  "isVendor": true,
  "isBuyer": true,
  "isSponsor": false
}
```

**Response:**
```json
{
  "success": true,
  "message": "Profile updated successfully",
  "data": {
    "user": {
      "id": "uuid",
      "email": "user@example.com",
      "firstName": "John",
      "lastName": "Doe",
      "displayName": "John Doe",
      "avatarUrl": "https://example.com/avatar.jpg",
      "bio": "Software Developer",
      "website": "https://johndoe.com",
      "location": "San Francisco, CA",
      "phone": "+1234567890",
      "role": "USER",
      "isVendor": true,
      "isBuyer": true,
      "isSponsor": false,
      "emailVerified": true,
      "isActive": true,
      "createdAt": "2025-01-01T00:00:00.000Z",
      "updatedAt": "2025-02-02T00:00:00.000Z"
    }
  }
}
```

#### 15. Refresh Token
```http
POST /api/auth/refresh-token
```

**Response:**
```json
{
  "success": true,
  "message": "Token refreshed successfully",
  "data": {
    "token": "new_jwt_token_here"
  }
}
```

#### 16. Deactivate Account
```http
POST /api/auth/deactivate-account
```

**Response:**
```json
{
  "success": true,
  "message": "Account deactivated successfully. You can reactivate within 30 days.",
  "data": {
    "deactivatedAt": "2025-02-02T00:00:00.000Z",
    "canBeReactivated": true,
    "reactivationWindowDays": 30
  }
}
```

#### 17. Get User Preferences
```http
GET /api/auth/preferences
```

**Response:**
```json
{
  "success": true,
  "data": {
    "preferences": {
      "notifications": {
        "email": true,
        "push": true,
        "marketing": false
      },
      "privacy": {
        "profileVisibility": "public",
        "showOnlineStatus": true,
        "showLastSeen": true
      },
      "display": {
        "theme": "light",
        "language": "en",
        "timezone": "UTC"
      },
      "emailFrequency": {
        "newsletter": "weekly",
        "updates": "immediate",
        "digest": true
      },
      "security": {
        "twoFactorEnabled": false,
        "loginAlerts": true,
        "suspiciousActivityAlerts": true
      }
    }
  }
}
```

#### 18. Update User Preferences
```http
PUT /api/auth/preferences
```

**Request Body:**
```json
{
  "preferences": {
    "notifications": {
      "email": true,
      "push": false,
      "marketing": true
    },
    "privacy": {
      "profileVisibility": "private",
      "showOnlineStatus": false,
      "showLastSeen": false
    },
    "display": {
      "theme": "dark",
      "language": "en",
      "timezone": "America/New_York"
    },
    "emailFrequency": {
      "newsletter": "monthly",
      "updates": "daily",
      "digest": false
    },
    "security": {
      "twoFactorEnabled": true,
      "loginAlerts": true,
      "suspiciousActivityAlerts": true
    }
  }
}
```

**Response:**
```json
{
  "success": true,
  "message": "Preferences updated successfully",
  "data": {
    "user": {
      "id": "uuid",
      "email": "user@example.com",
      "firstName": "John",
      "preferences": {
        "notifications": {
          "email": true,
          "push": false,
          "marketing": true
        },
        "privacy": {
          "profileVisibility": "private",
          "showOnlineStatus": false,
          "showLastSeen": false
        },
        "display": {
          "theme": "dark",
          "language": "en",
          "timezone": "America/New_York"
        },
        "emailFrequency": {
          "newsletter": "monthly",
          "updates": "daily",
          "digest": false
        },
        "security": {
          "twoFactorEnabled": true,
          "loginAlerts": true,
          "suspiciousActivityAlerts": true
        }
      }
    }
  }
}
```

---

### Admin Routes
**Authentication Required:** Admin or Moderator role required.

#### 19. Admin Deactivate Account
```http
POST /api/auth/admin/deactivate/:userId
```

**Response:**
```json
{
  "success": true,
  "message": "User account deactivated successfully by admin",
  "data": {
    "deactivatedUser": {
      "id": "uuid",
      "email": "user@example.com"
    },
    "deactivatedAt": "2025-02-02T00:00:00.000Z",
    "deactivatedBy": {
      "id": "admin_uuid",
      "email": "admin@example.com",
      "name": "Admin User"
    }
  }
}
```

#### 20. Admin Reactivate Account
```http
POST /api/auth/admin/reactivate/:userId
```

**Response:**
```json
{
  "success": true,
  "message": "User account reactivated successfully by admin",
  "data": {
    "reactivatedUser": {
      "id": "uuid",
      "email": "user@example.com",
      "isActive": true
    },
    "reactivatedAt": "2025-02-02T00:00:00.000Z",
    "reactivatedBy": {
      "id": "admin_uuid",
      "email": "admin@example.com",
      "name": "Admin User"
    }
  }
}
```

---

## OAuth Routes

### Public Routes

#### 1. Verify Google Token
```http
POST /api/oauth/google/verify
```

**Request Body:**
```json
{
  "token": "google_id_token_here",
  "redirectUri": "postmessage"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Google authentication successful",
  "user": {
    "id": "uuid",
    "email": "user@gmail.com",
    "firstName": "John",
    "lastName": "Doe",
    "displayName": "John Doe",
    "avatarUrl": "https://lh3.googleusercontent.com/...",
    "role": "USER",
    "emailVerified": true,
    "vendorProfile": null,
    "googleId": "google_user_id"
  },
  "token": "jwt_token_here",
  "isOAuth": true,
  "code": "GOOGLE_AUTH_SUCCESS"
}
```

#### 2. Get OAuth Config
```http
GET /api/oauth/config
```

**Response:**
```json
{
  "success": true,
  "config": {
    "google": {
      "enabled": true,
      "clientId": "your_google_client_id",
      "scope": "profile email",
      "redirectUri": "http://localhost:5173/oauth/callback"
    }
  }
}
```

### Protected Routes

#### 3. Unlink Google Account
```http
POST /api/oauth/google/unlink
```

**Response:**
```json
{
  "success": true,
  "message": "Google account unlinked successfully",
  "code": "GOOGLE_UNLINKED"
}
```

---

## Response Format

### Success Response
```json
{
  "success": true,
  "message": "Operation successful",
  "data": {
    // Response data
  }
}
```

### Error Response
```json
{
  "success": false,
  "error": "Error message",
  "code": "ERROR_CODE",
  "details": "Additional error details (development only)"
}
```

---

## Error Codes

### Authentication Errors
- `MISSING_TOKEN` - No authentication token provided
- `INVALID_TOKEN` - Invalid or expired token
- `TOKEN_EXPIRED` - Token has expired
- `NOT_AUTHENTICATED` - Authentication required

### Validation Errors
- `MISSING_REQUIRED_FIELDS` - Required fields missing
- `INVALID_EMAIL` - Invalid email format
- `INVALID_PASSWORD` - Password doesn't meet requirements
- `EMAIL_IN_USE` - Email already registered

### Account Errors
- `USER_NOT_FOUND` - User account not found
- `ACCOUNT_DEACTIVATED` - Account is deactivated
- `EMAIL_NOT_VERIFIED` - Email verification required
- `ACCOUNT_INACTIVE` - Account is inactive

### Authorization Errors
- `UNAUTHORIZED` - Insufficient permissions
- `ADMIN_REQUIRED` - Admin privileges required
- `FORBIDDEN` - Access forbidden

### OAuth Errors
- `OAUTH_NOT_CONFIGURED` - OAuth provider not configured
- `GOOGLE_AUTH_FAILED` - Google authentication failed
- `UNLINK_FAILED` - Failed to unlink OAuth account

### Rate Limiting
- `REACTIVATION_RATE_LIMITED` - Too many reactivation requests
- `RATE_LIMITED` - Too many requests

---

## Password Requirements

- Minimum 8 characters
- At least one lowercase letter
- At least one uppercase letter
- At least one number
- At least one special character (@$!%*?&)

---

## Notes

1. **Authentication**: Most endpoints require JWT token authentication. Include the token in the Authorization header or as a cookie.

2. **Email Verification**: New users receive a verification email after registration. Email must be verified for full account access.

3. **Password Reset**: Password reset tokens expire after 1 hour.

4. **Account Deactivation**: 
   - Users can deactivate their own accounts
   - Accounts can be reactivated within 30 days
   - Admin deactivations are permanent unless reactivated by admin

5. **Sessions**: Successful login creates a session that expires after 7 days.

6. **Security Logging**: All authentication actions are logged for security auditing.

7. **Cookies**: Auth tokens are stored in HTTP-only cookies for enhanced security.

8. **CORS**: Configure CORS settings in production to allow requests from your frontend domain.