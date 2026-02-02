import axios, { AxiosResponse } from 'axios';

// Interface definitions
interface MpesaAuthResponse {
  access_token: string;
  expires_in: string;
}

interface STKPushRequest {
  BusinessShortCode: string;
  Password: string;
  Timestamp: string;
  TransactionType: string;
  Amount: number;
  PartyA: string;
  PartyB: string;
  PhoneNumber: string;
  CallBackURL: string;
  AccountReference: string;
  TransactionDesc: string;
}

interface STKPushResponse {
  MerchantRequestID: string;
  CheckoutRequestID: string;
  ResponseCode: string;
  ResponseDescription: string;
  CustomerMessage: string;
}

interface QueryRequest {
  BusinessShortCode: string;
  Password: string;
  Timestamp: string;
  CheckoutRequestID: string;
}

interface QueryResponse {
  ResponseCode: string;
  ResponseDescription: string;
  MerchantRequestID: string;
  CheckoutRequestID: string;
  ResultCode: string;
  ResultDesc: string;
}

interface STKPushResult {
  success: boolean;
  data?: STKPushResponse;
  checkoutRequestID?: string;
  customerMessage?: string;
  responseCode?: string;
  error?: string;
  errorCode?: string;
}

interface QueryResult {
  success: boolean;
  data?: QueryResponse;
  resultCode?: string;
  resultDesc?: string;
  error?: any;
}

class MpesaService {
  private consumerKey: string;
  private consumerSecret: string;
  private baseURL: string;
  private authURL: string;
  private stkPushURL: string;
  private stkQueryURL: string;
  private callbackURL: string;
  private businessShortCode: string;
  private passkey: string;
  private accessToken: string | null = null;
  private tokenExpiry: number | null = null;

  constructor() {
    this.consumerKey = process.env['MPESA_CONSUMER_KEY'] || '';
    this.consumerSecret = process.env['MPESA_CONSUMER_SECRET'] || '';
    this.baseURL =
      process.env['MPESA_BASE_URL'] || 'https://sandbox.safaricom.co.ke';

    // Validate required environment variables
    if (!this.consumerKey || !this.consumerSecret) {
      throw new Error(
        'MPESA_CONSUMER_KEY and MPESA_CONSUMER_SECRET are required',
      );
    }

    this.authURL = `${this.baseURL}/oauth/v1/generate?grant_type=client_credentials`;
    this.stkPushURL = `${this.baseURL}/mpesa/stkpush/v1/processrequest`;
    this.stkQueryURL = `${this.baseURL}/mpesa/stkpushquery/v1/query`;

    this.callbackURL = process.env['MPESA_CALLBACK_URL'] || '';
    this.businessShortCode = process.env['MPESA_BUSINESS_SHORTCODE'] || '174379'; // Default sandbox shortcode
    this.passkey = process.env['MPESA_PASSKEY'] || '';

    // Validate business credentials
    if (!this.businessShortCode || !this.passkey) {
      console.warn(
        'MPESA_BUSINESS_SHORTCODE or MPESA_PASSKEY not set. Using sandbox defaults.',
      );
    }

    console.log('M-Pesa Service initialized:', {
      baseURL: this.baseURL,
      businessShortCode: this.businessShortCode,
      hasCallbackURL: !!this.callbackURL,
    });
  }

  /**
   * Generate access token from M-Pesa API
   */
  async generateAccessToken(): Promise<string> {
    try {
      // Create Basic Auth credentials
      const auth = Buffer.from(
        `${this.consumerKey}:${this.consumerSecret}`,
      ).toString('base64');

      console.log('🔄 Generating M-Pesa access token...');

      const response: AxiosResponse<MpesaAuthResponse> = await axios.get(
        this.authURL,
        {
          headers: {
            Authorization: `Basic ${auth}`,
            'Content-Type': 'application/json',
          },
          timeout: 15000, // 15 second timeout
        },
      );

      if (!response.data.access_token) {
        throw new Error('No access token received from M-Pesa');
      }

      this.accessToken = response.data.access_token;
      // Convert expires_in to milliseconds and set expiry with 5-minute buffer
      const expiresIn = parseInt(response.data.expires_in) * 1000;
      this.tokenExpiry = Date.now() + expiresIn - 300000; // 5 minutes buffer

      console.log('✅ M-Pesa token generated successfully');
      return this.accessToken;
    } catch (error: any) {
      console.error('❌ M-Pesa token generation error:', {
        status: error.response?.status,
        data: error.response?.data,
        message: error.message,
        url: this.authURL,
      });

      throw new Error(
        `Failed to generate M-Pesa access token: ${error.response?.data?.error_message || error.message}`,
      );
    }
  }

  /**
   * Ensure we have a valid access token
   */
  async ensureValidToken(): Promise<string> {
    if (
      !this.accessToken ||
      !this.tokenExpiry ||
      Date.now() >= this.tokenExpiry
    ) {
      await this.generateAccessToken();
    }
    return this.accessToken!;
  }

  /**
   * Generate timestamp in required format (YYYYMMDDHHmmss)
   */
  private generateTimestamp(): string {
    const now = new Date();
    return (
      now.getFullYear() +
      String(now.getMonth() + 1).padStart(2, '0') +
      String(now.getDate()).padStart(2, '0') +
      String(now.getHours()).padStart(2, '0') +
      String(now.getMinutes()).padStart(2, '0') +
      String(now.getSeconds()).padStart(2, '0')
    );
  }

  /**
   * Generate password for STK push
   */
  private generatePassword(): string {
    const timestamp = this.generateTimestamp();
    const dataToEncode = this.businessShortCode + this.passkey + timestamp;
    return Buffer.from(dataToEncode).toString('base64');
  }

  /**
   * Validate and format Kenyan phone numbers
   */
  validatePhoneNumber(phoneNumber: string): string {
    // Remove any non-digit characters
    const cleaned = phoneNumber.replace(/\D/g, '');

    console.log('🔍 Phone validation:', { original: phoneNumber, cleaned });

    // Mobile numbers (Safaricom, Airtel, Telkom)
    if (cleaned.length === 12 && cleaned.startsWith('2547')) {
      return cleaned; // 254712345678
    } else if (cleaned.length === 10 && cleaned.startsWith('07')) {
      return '254' + cleaned.substring(1); // 0712345678 → 254712345678
    } else if (cleaned.length === 9 && cleaned.startsWith('7')) {
      return '254' + cleaned; // 712345678 → 254712345678
    }

    // Landline numbers
    else if (cleaned.length === 12 && cleaned.startsWith('2541')) {
      return cleaned; // 254201234567, 254411234567
    } else if (cleaned.length === 9 && cleaned.startsWith('01')) {
      return '2541' + cleaned.substring(1); // 012345678 → 254112345678
    }

    // Other area codes
    else if (cleaned.length === 9 && cleaned.match(/^[4-6]\d{8}$/)) {
      return '254' + cleaned; // 412345678 → 254412345678
    }

    throw new Error(
      `Invalid Kenyan phone number: ${phoneNumber}\n` +
        `Supported formats:\n` +
        `• Mobile: 07XXXXXXXX, 2547XXXXXXXX\n` +
        `• Landline: 011XXXXXXX, 25411XXXXXXX\n` +
        `• Other: 041XXXXXXX, 051XXXXXXX, 061XXXXXXX`,
    );
  }

  /**
   * Initiate STK push payment
   */
  async initiateSTKPush(
    phoneNumber: string,
    amount: number,
    accountReference: string,
    transactionDesc: string = 'Payment',
  ): Promise<STKPushResult> {
    try {
      console.log('🔐 Ensuring valid M-Pesa token...');
      await this.ensureValidToken();

      const timestamp = this.generateTimestamp();
      const password = this.generatePassword();

      // Validate and format phone number
      const formattedPhone = this.validatePhoneNumber(phoneNumber);

      // Validate amount
      if (amount <= 0) {
        throw new Error('Amount must be greater than 0');
      }

      // Validate account reference
      if (!accountReference || accountReference.trim().length === 0) {
        throw new Error('Account reference is required');
      }

      const requestData: STKPushRequest = {
        BusinessShortCode: this.businessShortCode,
        Password: password,
        Timestamp: timestamp,
        TransactionType: 'CustomerPayBillOnline',
        Amount: Math.round(amount),
        PartyA: formattedPhone,
        PartyB: this.businessShortCode,
        PhoneNumber: formattedPhone,
        CallBackURL: this.callbackURL,
        AccountReference: accountReference.substring(0, 12), // Max 12 characters
        TransactionDesc: transactionDesc.substring(0, 13), // Max 13 characters
      };

      console.log('📤 M-Pesa STK Push Request:', {
        ...requestData,
        Password: '***', // Hide password in logs
        Timestamp: timestamp,
      });

      const response: AxiosResponse<STKPushResponse> = await axios.post(
        this.stkPushURL,
        requestData,
        {
          headers: {
            Authorization: `Bearer ${this.accessToken}`,
            'Content-Type': 'application/json',
          },
          timeout: 30000, // 30 second timeout
        },
      );

      console.log('📥 M-Pesa STK Push Response:', response.data);

      if (response.data.ResponseCode === '0') {
        return {
          success: true,
          data: response.data,
          checkoutRequestID: response.data.CheckoutRequestID,
          customerMessage: response.data.CustomerMessage,
          responseCode: response.data.ResponseCode,
        };
      } else {
        return {
          success: false,
          error: response.data.CustomerMessage,
          responseCode: response.data.ResponseCode,
        };
      }
    } catch (error: any) {
      console.error('❌ M-Pesa STK Push Error:', {
        status: error.response?.status,
        data: error.response?.data,
        message: error.message,
        phoneNumber,
        amount,
        accountReference,
      });

      return {
        success: false,
        error:
          error.response?.data?.errorMessage ||
          error.response?.data?.error_description ||
          error.message,
        errorCode: this.getErrorCode(error.response?.data),
      };
    }
  }

  /**
   * Query transaction status
   */
  async queryTransactionStatus(
    checkoutRequestID: string,
  ): Promise<QueryResult> {
    try {
      await this.ensureValidToken();

      const timestamp = this.generateTimestamp();
      const password = this.generatePassword();

      const requestData: QueryRequest = {
        BusinessShortCode: this.businessShortCode,
        Password: password,
        Timestamp: timestamp,
        CheckoutRequestID: checkoutRequestID,
      };

      console.log('🔍 M-Pesa Query Request:', {
        ...requestData,
        Password: '***',
        CheckoutRequestID: checkoutRequestID.substring(0, 10) + '...',
      });

      const response: AxiosResponse<QueryResponse> = await axios.post(
        this.stkQueryURL,
        requestData,
        {
          headers: {
            Authorization: `Bearer ${this.accessToken}`,
            'Content-Type': 'application/json',
          },
          timeout: 30000,
        },
      );

      console.log('📨 M-Pesa Query Response:', response.data);

      return {
        success: true,
        data: response.data,
        resultCode: response.data.ResultCode,
        resultDesc: response.data.ResultDesc,
      };
    } catch (error: any) {
      console.error('❌ M-Pesa Query Error:', {
        status: error.response?.status,
        data: error.response?.data,
        message: error.message,
        checkoutRequestID: checkoutRequestID.substring(0, 10) + '...',
      });
      return {
        success: false,
        error: error.response?.data || error.message,
      };
    }
  }

  /**
   * Get error code description
   */
  private getErrorCode(errorData: any): string {
    const errorCodes: Record<string | number, string> = {
      0: 'Success',
      1: 'Insufficient Funds',
      2: 'Less Than Minimum Transaction Value',
      3: 'More Than Maximum Transaction Value',
      4: 'Would Exceed Daily Transfer Limit',
      5: 'Would Exceed Minimum Balance',
      6: 'Unresolved Primary Party',
      7: 'Unresolved Receiver Party',
      8: 'Would Exceed Maximum Balance',
      11: 'Debit Account Invalid',
      12: 'Credit Account Invalid',
      13: 'Unresolved Debit Account',
      14: 'Unresolved Credit Account',
      15: 'Duplicate Detected',
      17: 'Internal Failure',
      20: 'Unresolved Initiator',
      26: 'Traffic blocking condition in place',
      1032: 'Request cancelled by user',
      1037: 'Timeout - User did not respond',
      2001: 'Initiator information is invalid',
      2002: 'Receiver party information is invalid',
      2003: 'Initiator information and receiver party information are invalid',
      2004: 'Transaction cannot be completed',
      2005: 'Transaction cannot be completed',
      2006: 'Transaction cannot be completed',
    };

    const code =
      errorData?.errorCode || errorData?.ResultCode || errorData?.responseCode;
    return errorCodes[code] || 'Unknown error';
  }

  /**
   * Verify callback signature (for webhook verification)
   */
  verifyCallbackSignature(body: any, signature: string): boolean {
    body;
    signature;
    // Implement callback signature verification if needed
    // This is a placeholder - M-Pesa doesn't typically use signatures in callbacks
    return true;
  }

  /**
   * Get service status (for health checks)
   */
  async getServiceStatus(): Promise<{
    status: 'healthy' | 'unhealthy';
    tokenValid: boolean;
    baseURL: string;
  }> {
    try {
      await this.ensureValidToken();
      return {
        status: 'healthy',
        tokenValid: true,
        baseURL: this.baseURL,
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        tokenValid: false,
        baseURL: this.baseURL,
      };
    }
  }
}

// Create and export singleton instance
const mpesaService = new MpesaService();
export default mpesaService;
