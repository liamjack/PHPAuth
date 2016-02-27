<?php

namespace PHPAuth;

class Configuration {
	const EMAIL_MINIMUM_LENGTH = 5;
	const EMAIL_MAXIMUM_LENGTH = 150;

	const PASSWORD_MINIMUM_LENGTH = 8;
	const PASSWORD_MAXIMUM_LENGTH = 72;
	const PASSWORD_MINIMUM_SCORE = 2;
	const PASSWORD_HASH_COST = 11;

	const SESSION_CHECK_IP_ADDRESS = false;
	const SESSION_PERSISTENT_TIME = '+1 month';
	const SESSION_NON_PERSISTENT_TIME = '+30 minutes';
}