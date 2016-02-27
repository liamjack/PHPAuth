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
    }

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

    public function doesUserExistByEmail($email) {
        $query = $this->dbh->prepare("SELECT * FROM user WHERE email = ?");
        $query->execute(array($email));

        if($query->rowCount() == 0) {
            return false;
        }

        return true;
    }

    public function addUser(\PHPAuth\User $user) {
        $query = $this->dbh->prepare("INSERT INTO user (email, password) VALUES (?, ?)");

        if(!$query->execute(array($user->getEmail(), $user->getPassword()))) {
            throw new \Exception("system_error");
        }
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