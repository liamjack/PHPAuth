<?php

namespace PHPAuth;

interface Database {
	
	/**
	 * Returns a user from the database by id, or NULL on failure
	 * @param 	int 	$userId 	The user Id to lookup
	 * @return 	User
	 */

	public function getUserById($userId);

	/**
	 * Returns a user from the database by email, or NULL on failure
	 * @param 	string 	$email 	The email address to lookup
	 * @return 	User
	 */

	public function getUserByEmail($email);

	/**
	 * Informs if a user exists with a given email address
	 * @param 	string 	$email 	The email address to lookup
	 * @return 	bool
	 */

	public function doesUserExistByEmail($email);

	/**
	 * Adds a user to the database
	 * @param 	User 	$user
	 * @throws 	Exception
	 */

	public function addUser(\PHPAuth\User $user);

	/**
	 * Adds a session to the database
	 * @param 	Session 	$session 	The session to add
	 * @throws 	Exception
	 */

	public function addSession(\PHPAuth\Session $session);

	/**
	 * Updates a session in the database
	 * @param 	Session 	$session 	The updated session
	 * @throws 	Exception
	 */

	public function updateSession(\PHPAuth\Session $session);

	/**
	 * Deletes a session from the database
	 * @param 	string 	$sessionUuid 	The session's UUID
	 * @throws 	Exception
	 */

	public function deleteSession($sessionUuid);

	/**
	 * Returns a session identified by it's UUID, or NULL
	 * @param 	string 	$sessionUuid 	The session's UUID
	 * @return 	Session
	 */

	public function getSession($sessionUuid);



}