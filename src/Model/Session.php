<?php

namespace PHPAuth\Model;

/**
 * @author Liam Jack <cuonic@cuonic.com>
 * @license MIT
 */
class Session
{
    private $uuid;
    private $userId;
    private $userAgent;
    private $ipAddress;
    private $creationDate;
    private $expiryDate;
    private $isPersistent;
    private $lastActiveDate;
    private $isUpdateRequired = false;

    /**
     * @param string $uuid
     * @param int    $userId
     * @param string $userAgent
     * @param string $ipAddress
     * @param int    $creationDate
     * @param int    $expiryDate
     * @param int    $lastActiveDate
     * @param bool   $isPersistent
     */
    public function __construct($uuid, $userId, $userAgent, $ipAddress, $creationDate, $expiryDate, $lastActiveDate, $isPersistent = false)
    {
        $this->uuid = $uuid;
        $this->userId = $userId;
        $this->userAgent = $userAgent;
        $this->ipAddress = $ipAddress;
        $this->creationDate = $creationDate;
        $this->expiryDate = $expiryDate;
        $this->lastActiveDate = $lastActiveDate;
        $this->isPersistent = $isPersistent;
    }

    /**
     * Returns the session's UUID.
     *
     * @return string
     */
    public function getUuid()
    {
        return $this->uuid;
    }

    /**
     * Returns the ID of the user associated with the session.
     *
     * @return int
     */
    public function getUserId()
    {
        return $this->userId;
    }

    /**
     * Returns the user agent associated with the session.
     *
     * @return string
     */
    public function getUserAgent()
    {
        return $this->userAgent;
    }

    /**
     * Returns the IP Address associated with the session.
     *
     * @return int
     */
    public function getIpAddress()
    {
        return $this->ipAddress;
    }

    /**
     * Modifies the IP address associated with the session.
     *
     * @param string $ipAddress
     */
    private function setIpAddress($ipAddress)
    {
        $this->isUpdateRequired = true;
        $this->ipAddress = $ipAddress;
    }

    /**
     * Returns the creation date (timestamp) of the session.
     *
     * @return int
     */
    public function getCreationDate()
    {
        return $this->creationDate;
    }

    /**
     * Returns the expiry date (timestamp) of the session.
     *
     * @return int
     */
    public function getExpiryDate()
    {
        return $this->expiryDate;
    }

    /**
     * Modifies the expiry date of the session.
     *
     * @param int $expiryDate
     */
    private function setExpiryDate($expiryDate)
    {
        $this->isUpdateRequired = true;
        $this->expiryDate = $expiryDate;
    }

    /**
     * Returns the date of last activity of the session.
     *
     * @return int
     */
    public function getLastActiveDate() {
        return $this->lastActiveDate;
    }

    /**
     * Modifies the date of last activity of the session.
     *
     * @param int $lastActiveDate
     */
    private function setLastActiveDate($lastActiveDate) {
        $this->isUpdateRequired = true;
        $this->lastActiveDate = $lastActiveDate;
    }

    /**
     * Indicates whether the session is persistent or not.
     *
     * @return bool
     */
    public function isPersistent()
    {
        return $this->isPersistent;
    }

    /**
     * Indicates whether the session has been updated during validation and requires updating.
     *
     * @return bool
     */
    public function isUpdateRequired()
    {
        return $this->isUpdateRequired;
    }

    /**
     * Check whether the current session is valid.
     *
     * @return bool
     */
    public function isValid()
    {
        $userAgent = $_SERVER['HTTP_USER_AGENT'];
        $ipAddress = $_SERVER['REMOTE_ADDR'];

        if ($userAgent !== $this->getUserAgent())
            return false;

        if ($ipAddress !== $this->getIpAddress()) {
            // Session IP differs from user's current IP

            if (\PHPAuth\Configuration::SESSION_CHECK_IP_ADDRESS)
                return false;

            // IP address verification is not enforced, update IP address stored in database
            $this->setIpAddress($ipAddress);
        }

        if (time() >= $this->getExpiryDate())
            return false;

        if (!$this->isPersistent())
            $this->setExpiryDate(strtotime(\PHPAuth\Configuration::SESSION_NON_PERSISTENT_TIME));

        $this->setLastActiveDate(time());

        // Session is valid
        return true;
    }

    /**
     * Returns an array containing the session's public information
     *
     * @return array
     */
    public function toArray() {
        return array(
            "uuid" => $this->getUuid(),
            "userId" => $this->getUserId(),
            "userAgent" => $this->getUserAgent(),
            "ipAddress" => $this->getIpAddress(),
            "creationDate" => date('c', $this->getCreationDate()),
            "expiryDate" => date('c', $this->getExpiryDate()),
            "lastActiveDate" => date('c', $this->getLastActiveDate()),
            "isPersistent" => $this->isPersistent()
        );
    }

    /**
     * Creates a new session for a given user.
     *
     * @param int  $userId       User's ID
     * @param bool $isPersistent Whether the session is persistent or not
     *
     * @return Session
     *
     * @throws Exception
     */
    public static function createSession($userId, $isPersistent = false)
    {
        self::validateIsPersistent($isPersistent);

        $creationDate = time();

        if ($isPersistent)
            $expiryDate = strtotime(\PHPAuth\Configuration::SESSION_PERSISTENT_TIME);
        else
            $expiryDate = strtotime(\PHPAuth\Configuration::SESSION_NON_PERSISTENT_TIME);

        $ipAddress = $_SERVER['REMOTE_ADDR'];
        $userAgent = $_SERVER['HTTP_USER_AGENT'];

        $uuid = \PHPAuth\Util::generateUuid();

        return new self($uuid, $userId, $userAgent, $ipAddress, $creationDate, $expiryDate, NULL, $isPersistent);
    }

    /**
     * Validates a user provided isPersistent value.
     *
     * @param bool $isPersistent
     *
     * @throws Exception
     */
    public static function validateIsPersistent($isPersistent)
    {
        if (!is_bool($isPersistent))
            throw new \Exception('is_persistent_invalid');
    }

    
}
