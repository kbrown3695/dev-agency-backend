// src/config/email.config.ts
import dotenv from 'dotenv';
dotenv.config();

// Email configuration
export const emailConfig = {
  service: process.env['EMAIL_SERVICE'] || 'gmail',
  host: process.env['EMAIL_HOST'] || 'smtp.gmail.com',
  port: parseInt(process.env['EMAIL_PORT'] || '587'),
  secure: process.env['EMAIL_SECURE'] === 'true',
  auth: {
    user: process.env['EMAIL_USER'] || '',
    pass: process.env['EMAIL_PASSWORD'] || '', // Use App Password for Gmail
  },
  from: {
    name: process.env['EMAIL_FROM_NAME'] || 'Dev-Agency',
    address: process.env['EMAIL_USER'] || 'noreply@dev-agency.com',
  },
};

// Email templates configuration
export const emailTemplates = {
  verification: {
    subject: 'Verify Your Email Address - Dev-Agency',
    template: 'email-verification.html',
  },
  welcome: {
    subject: 'Welcome to Dev-Agency!',
    template: 'welcome.html',
  },
  passwordReset: {
    subject: 'Reset Your Password - Dev-Agency',
    template: 'password-reset.html',
  },
  projectInvitation: {
    subject: 'Project Invitation - Dev-Agency',
    template: 'project-invitation.html',
  },
  bidNotification: {
    subject: 'New Bid on Your Project - Dev-Agency',
    template: 'bid-notification.html',
  },
  scheduleReminder: {
    subject: 'Upcoming Meeting Reminder - Dev-Agency',
    template: 'schedule-reminder.html',
  },
};

export default emailConfig;
