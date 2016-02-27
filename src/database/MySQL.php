<?php

namespace PHPAuth\Database;

class MySQL implements \PHPAuth\Database {

    private $dbh;

    /*
     * Initiates the database connection
     * @param $host
     * @param $username
     * @param $password
     * @param $databaseName
     * @throws PDOException
     */

    public function __construct($host, $username, $password, $databaseName) {
        $this->dbh = new \PDO("mysql:dbname={$databaseName};host={$host}", $username, $password);

        $this->dbh->setAttribute(\PDO::ATTR_DEFAULT_FETCH_MODE, \PDO::FETCH_ASSOC);
        $this->dbh->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
    }

    /**
     * Returns a user from the database by id, or NULL on failure
     * @param   int     $userId     The user Id to lookup
     * @return  User
     */

    public function getUserById($userId) {
        $query = $this->dbh->prepare("SELECT * FROM user WHERE id = ?");
        $query->execute(array($userId));

        if($query->rowCount() == 0) {
            return NULL;
        }

        $data = $query->fetch();

        return new \PHPAuth\User(
            $data['id'],
            $data['email'],
            $data['password']
        );
    }

    /**
     * Returns a user from the database by email, or NULL on failure
     * @param   string  $email  The email address to lookup
     * @return  User
     */

    public function getUserByEmail($email) {
        $query = $this->dbh->prepare("SELECT * FROM user WHERE email = ?");
        $query->execute(array($email));

        if($query->rowCount() == 0) {
            return NULL;
        }

        $data = $query->fetch();

        return new \PHPAuth\User(
            $data['id'],
            $data['email'],
            $data['password']
        );
    }

    /**
     * Informs if a user exists with a given email address
     * @param   string  $email  The email address to lookup
     * @return  bool
     */

    public function doesUserExistByEmail($email) {
        $query = $this->dbh->prepare("SELECT * FROM user WHERE email = ?");
        $query->execute(array($email));

        if($query->rowCount() == 0) {
            return false;
        }

        return true;
    }

    /**
     * Adds a user to the database
     * @param   User    $user
     * @throws  Exception
     */

    public function addUser(\PHPAuth\User $user) {
        $query = $this->dbh->prepare("INSERT INTO user (email, password) VALUES (?, ?)");
        $query->execute(
            array(
                $user->getEmail(),
                $user->getPassword()
            )
        );
    }

    /**
     * Updates a user in the database
     * @param   User    $user
     * @throws  Exception
     */

    public function updateUser(\PHPAuth\User $user) {
        $query = $this->dbh->prepare("UPDATE user SET email = ?, password = ? WHERE id = ?");
        $query->execute(
            array(
                $user->getEmail(),
                $user->getPassword(),
                $user->getId()
            )
        );
    }

    /**
     * Deletes a user from the database by user ID
     * @param   int     $userId
     * @throws  Exception
     */

    public function deleteUser($userId) {
        $query = $this->dbh->prepare("DELETE FROM user WHERE id = ?");
        $query->execute(
            array(
                $userId
            )
        );
    }

    /**
     * Adds a session to the database
     * @param   Session     The session to add
     * @throws  Exception
     */

    public function addSession(\PHPAuth\Session $session) {
        $query = $this->dbh->prepare("INSERT INTO session VALUES (?, ?, ?, ?, ?, ?, ?)");

        if(!$query->execute(array($session->getUuid(), $session->getUserId(), $session->getUserAgent(), $session->getIpAddress(), $session->getCreationDate(), $session->getExpiryDate(), $session->isPersistent()))) {
            throw new \Exception("system_error");
        }
    }

    /**
     * Updates a session in the database
     * @param   Session     $session    The updated session
     * @throws  Exception
     */

    public function updateSession(\PHPAuth\Session $session) {
        $query = $this->dbh->prepare("UPDATE session SET userAgent = ?, ipAddress = ?, expiryDate = ? WHERE uuid = ?");
        
        if(!$query->execute(array($session->getUserAgent(), $session->getIpAddress(), $session->getExpiryDate(), $session->getUuid()))) {
            throw new \Exception("system_error");
        }
    }

    /**
     * Deletes a session from the database
     * @param   string  $sessionUuid    The session's UUID
     * @throws  Exception
     */

    public function deleteSession($sessionUuid) {
        $query = $this->dbh->prepare("DELETE FROM session WHERE uuid = ?");

        if(!$query->execute(array($sessionUuid))) {
            throw new \Exception("system_error");
        }
    }

    /**
     * Returns a session identified by it's UUID, or NULL
     * @param   string  $sessionUuid    The session's UUID
     * @return  Session
     */

    public function getSession($sessionUuid) {
        $query = $this->dbh->prepare("SELECT * FROM session WHERE uuid = ?");
        $query->execute(array($sessionUuid));

        if($query->rowCount() == 0) {
            return NULL;
        }

        $data = $query->fetch();

        return new \PHPAuth\Session(
            $data['uuid'],
            $data['userId'],
            $data['userAgent'],
            $data['ipAddress'],
            $data['creationDate'],
            $data['expiryDate'],
            $data['isPersistent']
        );
    }


}