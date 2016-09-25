<?php

namespace PHPAuth;

/**
 * @author Liam Jack <cuonic@cuonic.com>
 * @license MIT
 */
class Configuration
{
    // The name of the site
    const SITE_NAME = 'Example Site';

    // Whether registration is enabled of not
    const REGISTRATION_ENABLED = true;

    // Minimum length for an email address
    const EMAIL_MINIMUM_LENGTH = 5;
    // Maximum length for an email address
    const EMAIL_MAXIMUM_LENGTH = 150;

    // Minimum length for a password
    const PASSWORD_MINIMUM_LENGTH = 8;
    // Minimum score for a password (see zxcvbn's scoring system)
    const PASSWORD_MINIMUM_SCORE = 2;
    // The cost of bcrypt hashing
    const PASSWORD_HASH_COST = 11;
    // The initial password hashing algorithm
    const PASSWORD_HASH_ALGO = 'sha256';

    // Whether to check the user's IP address against session IP address
    const SESSION_CHECK_IP_ADDRESS = false;
    // Validity of a peristent session
    const SESSION_PERSISTENT_TIME = '+1 month';
    // Validity of a non peristent session
    const SESSION_NON_PERSISTENT_TIME = '+30 minutes';

    // Name of the session cookie
    const SESSION_COOKIE_NAME = 'AuthSession';
    // Path of the session cookie
    const SESSION_COOKIE_PATH = '/';
    // Domain of the session cookie
    const SESSION_COOKIE_DOMAIN = '';
    // Whether the session cookie should only be transmitted via HTTPS
    const SESSION_COOKIE_SECURE = false;
    // Whether the session cookie should be only accessible via the HTTP protocol (not javascript)
    const SESSION_COOKIE_HTTPONLY = true;

    // Whether account activation is required
    const ACCOUNT_ACTIVATION_REQUIRED = false;
    // Amount of time an account activation link is valid for
    const ACCOUNT_ACTIVATION_EXPIRY = '+10 minutes';
    // Secret used to sign activation JWT
    const ACCOUNT_ACTIVATION_SECRET = '10101010-RandomStringGoesHere-01010101';
    // Subject of account activation email
    const ACCOUNT_ACTIVATION_SUBJECT = 'PHPAuth - Account activation required';
    // Path to Body template file of account activation email
    const ACCOUNT_ACTIVATION_BODY_FILE = __DIR__ . '/../templates/activation_email.html';
    // Path to AltBody template file of account activation email
    const ACCOUNT_ACTIVATION_ALTBODY_FILE = __DIR__ . '/../templates/activation_email.txt';


    // Whether emails should be sent via SMTP or not
    const MAIL_SMTP = false;
    // SMTP Hostname
    const MAIL_SMTP_HOSTNAME = 'smtp1.example.com';
    // Whether SMTP authentication is required or not
    const MAIL_SMTP_AUTH = true;
    // SMTP Username
    const MAIL_SMTP_USERNAME = 'user@example.com';
    // SMTP Password
    const MAIL_SMTP_PASSWORD = 'password';
    // SMTP Security
    const MAIL_SMTP_SECURE = 'tls';
    // SMTP Port
    const MAIL_SMTP_PORT = 587;

    // Email to appear as sender of email
    const MAIL_FROM_EMAIL = 'no-reply@example.com';
    // Name to appear as sender of email
    const MAIL_FROM_NAME = 'PHPAuth';

}
