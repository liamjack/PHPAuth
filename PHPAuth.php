<?php

namespace PHPAuth;

/**
 * @author Liam Jack <cuonic@cuonic.com>
 * @license MIT
 */

class PHPAuth {
	private $database;

	public function __construct(Database $database) {
		$this->database = $database;
	}

	/**
	 * Allows a user to authenticate and creates a new session
	 * @param  string 	$email 		User's email address
	 * @param  string 	$password 	User's password
	 * @return session
	 * @throws Exception
	 */

	public function login($email, $password, $isPersistent = false) {
		// Validate email address
		User::validateEmail($email);

		// Validate password
		User::validatePassword($password);

		// Get user with provided email address
		$user = $this->database->getUserByEmail($email);

		if($user == NULL) {
			// User does not exist
			throw new \Exception("email_password_incorrect");
		}

		if(!$user->verifyPassword($password)) {
			// Provided password doesn't match the user's password
			throw new \Exception("email_password_incorrect");
		}

		// Create a new session
		$session = Session::createSession($user->getId(), $isPersistent);

		// Add session to database
		$this->database->addSession($session);

		// Return session
		return $session;
	}

	/**
	 * Creates a new user account
	 * @param 	string $email 			User's email address
	 * @param 	string $password 		User's desired password
	 * @param 	string $repeatPassword	User's desired password, repeated to prevent typos
	 * @throws 	Exception
	 */

	public function register($email, $password, $repeatPassword) {
		// Validate email address
		User::validateEmail($email);

		// Validate password
		User::validatePassword($password);

		if($password !== $repeatPassword) {
			// Password and password confirmation do not match
			throw new \Exception("password_no_match");
		}

		if($this->database->doesUserExistByEmail($email)) {
			// User with this email address already exists
			throw new \Exception("email_used");
		}

		// Create new user
		$user = User::createUser($email, $password);

		// Add user to database
		$this->database->addUser($user);
	}

	/**
	 * Checks whether a user's session is valid or not and performs
	 * modifications / deletions of sessions when necessary
	 * @param 	string 	$sessionUuid	The session's UUID
	 * @return 	bool
	 */

	public function isSessionValid($sessionUuid) {
		// Validate the session's UUID
		if(!Session::validateUuid($sessionUuid)) {
			return false;
		}

		// Fetch the session from the database
		$session = $this->database->getSession($sessionUuid);

		if($session == NULL) {
			// Session doesn't exist
			return false;
		}

		if(!$session->isValid()) {
			// Session is invalid, delete
			$this->database->deleteSession($sessionUuid);
			return false;
		}

		if($session->isUpdateRequired()) {
			// Session has been updated during verification, push update to database
			$this->database->updateSession($session);
		}

		return true;
	}
}