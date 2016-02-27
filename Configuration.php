<?php

namespace PHPAuth;

/**
 * @author Liam Jack <cuonic@cuonic.com>
 * @license MIT
 */

class Configuration {
	// Whether registration is enabled of not
	const REGISTRATION_ENABLED = true;

	// Minimum length for an email address
	const EMAIL_MINIMUM_LENGTH = 5;
	// Maximum length for an email address
	const EMAIL_MAXIMUM_LENGTH = 150;

	// Minimum length for a password
	const PASSWORD_MINIMUM_LENGTH = 8;
	// Maximum length for a password
	const PASSWORD_MAXIMUM_LENGTH = 72;
	// Minimum score for a password (see zxcvbn's scoring system)
	const PASSWORD_MINIMUM_SCORE = 2;
	// The cost of bcrypt hashing
	const PASSWORD_HASH_COST = 11;

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
	const SESSION_COOKIE_HTTPONLY = TRUE;
}