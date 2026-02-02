// src/services/email.service.ts
import nodemailer from 'nodemailer';
import fs from 'fs';
import path from 'path';
import { emailConfig, emailTemplates } from '../config/email.config.js';

// Types
export interface EmailOptions {
  to: string | string[];
  subject?: string;
  text?: string;
  html?: string;
  template?: keyof typeof emailTemplates;
  templateData?: Record<string, any>;
  cc?: string | string[];
  bcc?: string | string[];
}

export interface EmailResponse {
  success: boolean;
  messageId?: string;
  error?: string;
}

class EmailService {
  private transporter: nodemailer.Transporter;
  private templatesDir: string;

  constructor() {
    // Create transporter
    this.transporter = nodemailer.createTransport({
      service: emailConfig.service,
      host: emailConfig.host,
      port: emailConfig.port,
      secure: emailConfig.secure,
      auth: emailConfig.auth,
    });

    // Verify connection configuration
    this.verifyConnection();

    // Set templates directory
    this.templatesDir = path.join(process.cwd(), 'src', 'templates', 'emails');
  }

  // Verify email connection
  private async verifyConnection(): Promise<void> {
    try {
      await this.transporter.verify();
      console.log('✅ Email service connected successfully');
    } catch (error) {
      console.error('❌ Email service connection failed:', error);
    }
  }

  // Load email template
  private loadTemplate(
    templateName: string,
    data: Record<string, any> = {},
  ): string {
    try {
      const templatePath = path.join(this.templatesDir, templateName);

      if (!fs.existsSync(templatePath)) {
        console.warn(`Template not found: ${templateName}, using default`);
        return this.generateDefaultHTML(data);
      }

      let template = fs.readFileSync(templatePath, 'utf-8');

      // Replace template variables
      Object.keys(data).forEach((key) => {
        const placeholder = `{{${key}}}`;
        template = template.replace(
          new RegExp(placeholder, 'g'),
          data[key] || '',
        );
      });

      return template;
    } catch (error) {
      console.error('Error loading template:', error);
      return this.generateDefaultHTML(data);
    }
  }

  // Generate default HTML email
  private generateDefaultHTML(data: Record<string, any> = {}): string {
    return `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Dev-Agency</title>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: #4F46E5; color: white; padding: 20px; text-align: center; }
            .content { padding: 30px; background: #f9f9f9; }
            .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
            .button { display: inline-block; padding: 12px 24px; background: #4F46E5; color: white; text-decoration: none; border-radius: 5px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>Dev-Agency</h1>
            </div>
            <div class="content">
              ${data['message'] || 'Thank you for using Dev-Agency!'}
              ${data['actionUrl'] ? `<p><a href="${data['actionUrl']}" class="button">${data['actionText'] || 'Take Action'}</a></p>` : ''}
            </div>
            <div class="footer">
              <p>© ${new Date().getFullYear()} Dev-Agency. All rights reserved.</p>
              <p>This email was sent to ${data['to'] || 'you'}.</p>
            </div>
          </div>
        </body>
      </html>
    `;
  }

  // Send email
  async sendEmail(options: EmailOptions): Promise<EmailResponse> {
    try {
      const { to, subject, text, html, template, templateData, cc, bcc } =
        options;

      // Determine email content
      let finalHtml = html;
      let finalSubject = subject;
      let finalText = text;

      // Use template if specified
      if (template && emailTemplates[template]) {
        const templateConfig = emailTemplates[template];
        finalSubject = subject || templateConfig.subject;
        finalHtml = this.loadTemplate(templateConfig.template, templateData);
        finalText =
          text || `Please view this email in an HTML-enabled email client.`;
      }

      // Prepare mail options
      const mailOptions: nodemailer.SendMailOptions = {
        from: {
          name: emailConfig.from.name,
          address: emailConfig.from.address,
        },
        to: Array.isArray(to) ? to.join(', ') : to,
        subject: finalSubject || 'Notification from Dev-Agency',
        text: finalText,
        html: finalHtml,
      };

      // Add CC if provided
      if (cc) {
        mailOptions.cc = Array.isArray(cc) ? cc.join(', ') : cc;
      }

      // Add BCC if provided
      if (bcc) {
        mailOptions.bcc = Array.isArray(bcc) ? bcc.join(', ') : bcc;
      }

      // Send email
      const info = await this.transporter.sendMail(mailOptions);

      console.log(`📧 Email sent to ${to}: ${info.messageId}`);

      return {
        success: true,
        messageId: info.messageId,
      };
    } catch (error) {
      console.error('❌ Error sending email:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  // Send verification email
  async sendVerificationEmail(
    to: string,
    verificationLink: string,
    userName: string = 'User',
  ): Promise<EmailResponse> {
    return this.sendEmail({
      to,
      template: 'verification',
      templateData: {
        userName,
        verificationLink,
        year: new Date().getFullYear(),
      },
    });
  }

  // Send welcome email
  async sendWelcomeEmail(
    to: string,
    userName: string = 'User',
  ): Promise<EmailResponse> {
    return this.sendEmail({
      to,
      template: 'welcome',
      templateData: {
        userName,
        dashboardLink: `${process.env['FRONTEND_URL'] || 'http://localhost:3000'}/dashboard`,
        year: new Date().getFullYear(),
      },
    });
  }

  // Send password reset email
  async sendPasswordResetEmail(
    to: string,
    resetLink: string,
    userName: string = 'User',
  ): Promise<EmailResponse> {
    return this.sendEmail({
      to,
      template: 'passwordReset',
      templateData: {
        userName,
        resetLink,
        year: new Date().getFullYear(),
        expiryTime: '1 hour',
      },
    });
  }

  // Send project invitation email
  async sendProjectInvitation(
    to: string,
    projectTitle: string,
    invitationLink: string,
    inviterName: string,
    userName: string = 'User',
  ): Promise<EmailResponse> {
    return this.sendEmail({
      to,
      template: 'projectInvitation',
      templateData: {
        userName,
        projectTitle,
        invitationLink,
        inviterName,
        year: new Date().getFullYear(),
      },
    });
  }

  // Send bid notification email
  async sendBidNotification(
    to: string,
    projectTitle: string,
    bidAmount: number,
    bidderName: string,
    projectLink: string,
    userName: string = 'User',
  ): Promise<EmailResponse> {
    return this.sendEmail({
      to,
      template: 'bidNotification',
      templateData: {
        userName,
        projectTitle,
        bidAmount: `$${bidAmount.toLocaleString()}`,
        bidderName,
        projectLink,
        year: new Date().getFullYear(),
      },
    });
  }

  // Send schedule reminder email
  async sendScheduleReminder(
    to: string,
    scheduleTitle: string,
    startTime: Date,
    meetingLink: string,
    userName: string = 'User',
  ): Promise<EmailResponse> {
    const formattedTime = startTime.toLocaleString('en-US', {
      weekday: 'long',
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      timeZoneName: 'short',
    });

    return this.sendEmail({
      to,
      template: 'scheduleReminder',
      templateData: {
        userName,
        scheduleTitle,
        startTime: formattedTime,
        meetingLink,
        year: new Date().getFullYear(),
      },
    });
  }

  // Test email connection
  async testConnection(): Promise<boolean> {
    try {
      await this.transporter.verify();
      return true;
    } catch (error) {
      console.error('Email connection test failed:', error);
      return false;
    }
  }

  // Get email service status
  getStatus() {
    return {
      service: emailConfig.service,
      user: emailConfig.auth.user,
      from: emailConfig.from,
      isConnected: this.transporter ? true : false,
    };
  }
}

// Create singleton instance
export const emailService = new EmailService();

export default emailService;
