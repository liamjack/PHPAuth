<?php

namespace PHPAuth;

/**
 * @author Liam Jack <cuonic@cuonic.com>
 * @license MIT
 */

class Session {
    private $uuid;
    private $userId;
    private $userAgent;
    private $ipAddress;
    private $creationDate;
    private $expiryDate;
    private $isPersistent;
    private $isUpdateRequired = false;

    /**
     * @param   string  $uuid
     * @param   int     $userId
     * @param   string  $userAgent
     * @param   string  $ipAddress
     * @param   int     $creationDate
     * @param   int     $expiryDate
     * @param   bool    $isPersistent
     */

    public function __construct($uuid, $userId, $userAgent, $ipAddress, $creationDate, $expiryDate, $isPersistent = false) {
        $this->uuid = $uuid;
        $this->userId = $userId;
        $this->userAgent = $userAgent;
        $this->ipAddress = $ipAddress;
        $this->creationDate = $creationDate;
        $this->expiryDate = $expiryDate;
        $this->isPersistent = $isPersistent;
    }

    /**
     * Returns the session's UUID
     * @return  string
     */

    public function getUuid() {
        return $this->uuid;
    }

    /**
     * Returns the ID of the user associated with the session
     * @return  int
     */

    public function getUserId() {
        return $this->userId;
    }

    /**
     * Returns the user agent associated with the session
     * @return  string
     */

    public function getUserAgent() {
        return $this->userAgent;
    }

    /**
     * Returns the IP Address associated with the session
     * @return  int
     */

    public function getIpAddress() {
        return $this->ipAddress;
    }

    /**
     * Modifies the IP address associated with the session
     * @param   string  $ipAddress
     */

    private function setIpAddress($ipAddress) {
        $this->isUpdateRequired = true;
        $this->ipAddress = $ipAddress;
    }

    /**
     * Returns the creation date (timestamp) of the session
     * @return  int
     */

    public function getCreationDate() {
        return $this->creationDate;
    }

    /**
     * Returns the expiry date (timestamp) of the session
     * @return  int
     */

    public function getExpiryDate() {
        return $this->expiryDate;
    }

    /**
     * Modifies the expiry date of the session
     * @param   int     $expiryDate
     */

    private function setExpiryDate($expiryDate) {
        $this->isUpdateRequired = true;
        $this->expiryDate = $expiryDate;
    }

    /**
     * Indicates whether the session is persistent or not
     * @return  bool
     */

    public function isPersistent() {
        return $this->isPersistent;
    }

    /**
     * Indicates whether the session has been updated during validation and requires updating
     * @return  bool
     */

    public function isUpdateRequired() {
        return $this->isUpdateRequired;
    }

    /**
     * Check whether the current session is valid
     * @return bool
     */

    public function isValid() {
        $userAgent = $_SERVER['HTTP_USER_AGENT'];
        $ipAddress = $_SERVER['REMOTE_ADDR'];

        if($userAgent !== $this->getUserAgent()) {
            // Session user agent differs from user's current user agent: session invalid
            return false;
        }

        if($ipAddress !== $this->getIpAddress()) {
            // Session IP differs from user's current IP

            if(Configuration::SESSION_CHECK_IP_ADDRESS) {
                // IP address verification is enforced: session invalid
                return false;
            }

            // IP address verification is not enforced, update IP address stored in database
            $this->setIpAddress($ipAddress);
        }

        if(time() >= $this->getExpiryDate()) {
            // Session has expired
            return false;
        }

        if(!$this->isPersistent()) {
            // Session is non persistent, update session expiry date since the session is still in use
            $this->setExpiryDate(strtotime(Configuration::SESSION_NON_PERSISTENT_TIME));
        }

        // Session is valid
        return true;
    }

    /**
     * Generates a random UUID
     * @return  string
     */

    public static function generateUuid() {
        return sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff ),
            mt_rand( 0, 0xffff ),
            mt_rand( 0, 0x0fff ) | 0x4000,
            mt_rand( 0, 0x3fff ) | 0x8000,
            mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff )
        );
    }

    /**
     * Creates a new session for a given user
     * @param   int     $userId         User's ID
     * @param   bool    $isPersistent   Whether the session is persistent or not
     * @return  Session
     * @throws  Exception
     */

    public static function createSession($userId, $isPersistent = false) {
        self::validateIsPersistent($isPersistent);

        $creationDate = time();

        if($isPersistent) {
            $expiryDate = strtotime(Configuration::SESSION_PERSISTENT_TIME);
        } else {
            $expiryDate = strtotime(Configuration::SESSION_NON_PERSISTENT_TIME);
        }

        $ipAddress = $_SERVER['REMOTE_ADDR'];
        $userAgent = $_SERVER['HTTP_USER_AGENT'];

        $uuid = self::generateUuid();

        return new Session($uuid, $userId, $userAgent, $ipAddress, $creationDate, $expiryDate, $isPersistent);
    }

    /**
     * Validates a user provided isPersistent value
     * @param bool $isPersistent
     * @throws Exception
     */

    public static function validateIsPersistent($isPersistent) {
        if(!is_bool($isPersistent)) {
            throw new \Exception("is_persistent_invalid");
        }
    }

    /**
     * Validates a session UUID
     * @param   string  $sessionUuid    The session's UUID
     * @throws  Exception
     */

    public static function validateUuid($sessionUuid) {
        if(preg_match('/^([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$/', $sessionUuid) == 1) {
            return true;
        }

        return false;
    }
}