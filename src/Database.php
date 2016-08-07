<?php

namespace PHPAuth;

interface Database
{
    /**
     * Returns a user from the database by id, or NULL on failure.
     *
     * @param int $userId The user Id to lookup
     *
     * @return User
     */
    public function getUserById($userId);

    /**
     * Returns a user from the database by email, or NULL on failure.
     *
     * @param string $email The email address to lookup
     *
     * @return User
     */
    public function getUserByEmail($email);

    /**
     * Adds a user to the database.
     *
     * @param User $user
     *
     * @throws Exception
     */
    public function addUser(\PHPAuth\Model\User $user);

    /**
     * Updates a user in the database.
     *
     * @param User $user
     *
     * @throws Exception
     */
    public function updateUser(\PHPAuth\Model\User $user);

    /**
     * Deletes a user from the database by user ID.
     *
     * @param int $userId
     *
     * @throws Exception
     */
    public function deleteUser($userId);

    /**
     * Adds a session to the database.
     *
     * @param Session $session The session to add
     *
     * @throws Exception
     */
    public function addSession(\PHPAuth\Model\Session $session);

    /**
     * Updates a session in the database.
     *
     * @param Session $session The updated session
     *
     * @throws Exception
     */
    public function updateSession(\PHPAuth\Model\Session $session);

    /**
     * Deletes a session from the database.
     *
     * @param string $sessionUuid The session's UUID
     *
     * @throws Exception
     */
    public function deleteSession($sessionUuid);

    /**
     * Returns a session identified by it's UUID, or NULL.
     *
     * @param string $sessionUuid The session's UUID
     *
     * @return Session
     */
    public function getSession($sessionUuid);

    /**
     * Returns an array of active sessions belonging to the specified user
     *
     * @param int $userId The user's id
     *
     * @return array
     */
    public function getSessionsByUserId($userId);
}
