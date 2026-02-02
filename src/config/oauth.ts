// Google OAuth 2.0 Configuration
export const googleOAuthConfig = {
  clientID: process.env["GOOGLE_CLIENT_ID"] || '',
  clientSecret: process.env["GOOGLE_CLIENT_SECRET"] || '',
  callbackURL:
    process.env["GOOGLE_CALLBACK_URL"] ||
    'http://localhost:5000/api/auth/google/callback',
  scope: [
    'profile',
    'email',
    'https://www.googleapis.com/auth/userinfo.profile',
    'https://www.googleapis.com/auth/userinfo.email',
  ],
};

// Validate Google OAuth configuration
export const validateGoogleConfig = () => {
  if (!googleOAuthConfig.clientID || !googleOAuthConfig.clientSecret) {
    throw new Error(
      'Google OAuth configuration is missing. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in .env',
    );
  }

  console.log('✅ Google OAuth Configuration:', {
    clientID: googleOAuthConfig.clientID ? 'Set' : 'Missing',
    clientSecret: googleOAuthConfig.clientSecret ? 'Set' : 'Missing',
    callbackURL: googleOAuthConfig.callbackURL,
  });

  return true;
};

// OAuth User Profile Interface
export interface GoogleProfile {
  id: string;
  displayName: string;
  name: {
    familyName?: string;
    givenName?: string;
  };
  emails: Array<{ value: string; verified?: boolean }>;
  photos: Array<{ value: string }>;
  provider: 'google';
  _raw: string;
  _json: {
    sub: string;
    name: string;
    given_name?: string;
    family_name?: string;
    picture?: string;
    email: string;
    email_verified: boolean;
    locale?: string;
  };
}

// OAuth Token Response
export interface OAuthTokenResponse {
  accessToken: string;
  refreshToken?: string;
  expiresIn?: number;
  tokenType?: string;
}

// OAuth User Data
export interface OAuthUserData {
  provider: string;
  providerId: string;
  email: string;
  firstName?: string;
  lastName?: string;
  displayName?: string;
  avatarUrl?: string;
  emailVerified: boolean;
  rawProfile: any;
}
