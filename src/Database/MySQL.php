<?php

namespace PHPAuth\database;

class MySQL implements \PHPAuth\Database
{
    private $dbh;

    /**
     * Initiates the database connection
     * 
     * @param   string  $host
     * @param   string  $username
     * @param   string  $password
     * @param   string  $databaseName
     *
     * @throws  PDOException
     */

    public function __construct($host, $username, $password, $databaseName)
    {
        $this->dbh = new \PDO("mysql:dbname={$databaseName};host={$host}", $username, $password);

        $this->dbh->setAttribute(\PDO::ATTR_DEFAULT_FETCH_MODE, \PDO::FETCH_ASSOC);
        $this->dbh->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
    }

    /**
     * Returns a user from the database by id, or NULL on failure.
     *
     * @param int $userId The user Id to lookup
     *
     * @return User
     */
    public function getUserById($userId)
    {
        $query = $this->dbh->prepare('
            SELECT
                *
            FROM
                user
            WHERE
                user_id = ?
        ');

        $query->execute(array(
            $userId
        ));

        $row = $query->fetch();

        return self::newUser($row);
    }

    /**
     * Returns a user from the database by email, or NULL on failure.
     *
     * @param string $email The email address to lookup
     *
     * @return User
     */
    public function getUserByEmail($email)
    {
        $query = $this->dbh->prepare('
            SELECT
                *
            FROM
                user
            WHERE
                user_email = ?
        ');
        
        $query->execute(array(
            $email
        ));

        $row = $query->fetch();

        return self::newUser($row);
    }

    /**
     * Adds a user to the database.
     *
     * @param User $user
     *
     * @throws Exception
     */
    public function addUser(\PHPAuth\Model\User $user)
    {
        $query = $this->dbh->prepare('
            INSERT INTO
                user (user_email, user_password_hash)
            VALUES
                (?, ?)
        ');

        $query->execute(array(
            $user->getEmail(),
            $user->getPasswordHash(),
        ));
    }

    /**
     * Updates a user in the database.
     *
     * @param User $user
     *
     * @throws Exception
     */
    public function updateUser(\PHPAuth\Model\User $user)
    {
        $query = $this->dbh->prepare('
            UPDATE
                user
            SET
                user_email = ?,
                user_password_hash = ?,
                user_is_activated = ?
            WHERE
                user_id = ?
        ');

        $query->execute(array(
            $user->getEmail(),
            $user->getPasswordHash(),
            $user->isActivated(),
            $user->getId(),
        ));
    }

    /**
     * Deletes a user from the database by user ID.
     *
     * @param int $userId
     *
     * @throws Exception
     */
    public function deleteUser($userId)
    {
        $query = $this->dbh->prepare('
            DELETE FROM
                user
            WHERE
                user_id = ?
            ');
        
        $execute = $query->execute(array(
            $userId
        ));

        if(!$execute) {
            throw new \Exception("system_error");
        }
    }

    /**
     * Adds a session to the database.
     *
     * @param   Session     The session to add
     *
     * @throws Exception
     */
    public function addSession(\PHPAuth\Model\Session $session)
    {
        $query = $this->dbh->prepare('
            INSERT INTO
                session
            VALUES
                (?, ?, ?, ?, ?, ?, ?, ?)
        ');

        $execute = $query->execute(array(
            $session->getUuid(),
            $session->getUserId(),
            $session->getUserAgent(),
            $session->getIpAddress(),
            $session->getCreationDate(),
            $session->getExpiryDate(),
            $session->getLastActiveDate(),
            $session->isPersistent()
        ));

        if (!$execute) {
            throw new \Exception('system_error');
        }
    }

    /**
     * Updates a session in the database.
     *
     * @param Session $session The updated session
     *
     * @throws Exception
     */
    public function updateSession(\PHPAuth\Model\Session $session)
    {
        $query = $this->dbh->prepare('
            UPDATE
                session
            SET
                session_user_agent = ?,
                session_ip_address = ?,
                session_expiry_date = ?,
                session_last_active_date = ?
            WHERE
                session_uuid = ?
        ');

        $execute = $query->execute(array(
            $session->getUserAgent(),
            $session->getIpAddress(),
            $session->getExpiryDate(),
            $session->getLastActiveDate(),
            $session->getUuid()
        ));

        if (!$execute) {
            throw new \Exception("system_error");
        }
    }

    /**
     * Deletes a session from the database.
     *
     * @param string $sessionUuid The session's UUID
     *
     * @throws Exception
     */
    public function deleteSession($sessionUuid)
    {
        $query = $this->dbh->prepare('
            DELETE FROM
                session
            WHERE
                session_uuid = ?
        ');

        $execute = $query->execute(array(
            $sessionUuid
        ));

        if (!$execute) {
            throw new \Exception('system_error');
        }
    }

    /**
     * Returns a session identified by it's UUID, or NULL.
     *
     * @param string $sessionUuid The session's UUID
     *
     * @return Session
     */
    public function getSession($sessionUuid)
    {
        $query = $this->dbh->prepare('
            SELECT
                *
            FROM
                session
            WHERE
                session_uuid = ?
        ');

        $query->execute(array(
            $sessionUuid
        ));

        $row = $query->fetch();

        return self::newSession($row);
    }

    /**
     * Returns an array of active sessions belonging to the specified user
     *
     * @param int $userId The user's id
     *
     * @return array
     */
    public function getSessionsByUserId($userId)
    {
        $query = $this->dbh->prepare('
            SELECT *
            FROM
                session
            WHERE
                session_user_id = ?
        ');

        $query->execute(array(
            $userId
        ));

        $sessions = array();

        while($row = $query->fetch()) {
            $sessions[] = self::newSession($row);
        }

        return $sessions;
    }

    /**
     * Returns a log entry identified by it's ID
     *
     * @param   int     $logId
     *
     * @return  Log
     */
    public function getLogById($logId) {
        $query = $this->dbh->prepare("
            SELECT *
            FROM
                log
            WHERE
                log_id = ?
        ");

        $query->execute(array(
            $logId
        ));

        $row = $query->fetch();

        return self::newLog($row);
    }

    /**
     * Returns an array of log entries belonging to a user identified by ID
     *
     * @param   int     $userId
     *
     * @return  array
     */
    public function getLogsByUserId($userId) {
        $query = $this->dbh->prepare("
            SELECT *
            FROM
                log
            WHERE
                log_user_id = ?
        ");

        $query->execute(array(
            $userId
        ));

        $logs = array();

        while($row = $query->fetch()) {
            $logs[] = self::newLog($row);
        }

        return $logs;
    }

    /**
     * Adds a new log entry to the database
     *
     * @param   Log     $log
     */
    public function addLog(\PHPAuth\Model\Log $log) {
        $query = $this->dbh->prepare("
            INSERT INTO
                log (
                    log_user_id,
                    log_action,
                    log_comment,
                    log_ip_address,
                    log_date
                )
            VALUES
                (?, ?, ?, ?, ?)
        ");

        $query->execute(array(
            $log->getUserId(),
            $log->getAction(),
            $log->getComment(),
            $log->getIpAddress(),
            $log->getDate()
        ));
    }

    /**
     * Creates a new user from a database row
     *
     * @param array $row
     *
     * @return \PHPAuth\Model\User
     */
    private static function newUser($row) {
        if (!$row) {
            return false;
        }

        return new \PHPAuth\Model\User(
            $row['user_id'],
            $row['user_email'],
            $row['user_password_hash'],
            $row['user_is_activated']
        );
    }

    /**
     * Creates a new session from a database row
     *
     * @param   array   $row
     * 
     * @return \PHPAuth\Model\Session
     */
    private static function newSession($row) {
        if (!$row) {
            return false;
        }

        return new \PHPAuth\Model\Session(
            $row['session_uuid'],
            $row['session_user_id'],
            $row['session_user_agent'],
            $row['session_ip_address'],
            $row['session_creation_date'],
            $row['session_expiry_date'],
            $row['session_last_active_date'],
            $row['session_is_persistent']
        );
    }

    /**
     * Creates a new log entry from a database row
     *
     * @param   array   $row
     * 
     * @return  \PHPAuth\Model\Log
     */
    private static function newLog($row) {
        if(!$row) {
            return false;
        }

        return new \PHPAuth\Model\Log(
            $row['log_id'],
            $row['log_user_id'],
            $row['log_action'],
            $row['log_comment'],
            $row['log_ip_address'],
            $row['log_date']
        );
    }
}
