<?php

namespace PHPAuth\Model;

class Log
{
    private $id;
    private $userId;
    private $action;
    private $comment;
    private $ipAddress;
    private $date;

    public function __construct($id, $userId, $action, $comment, $ipAddress, $date) {
        $this->id = $id;
        $this->userId = $userId;
        $this->action = $action;
        $this->comment = $comment;
        $this->ipAddress = $ipAddress;
        $this->date = $date;
    }

    /**
     * Returns the log's ID
     *
     * @return  int
     */
    public function getId() {
        return $this->id;
    }

    /**
     * Returns the ID of the user associated with the log entry
     *
     * @return int
     */
    public function getUserId() {
        return $this->userId;
    }

    /**
     * Returns the action performed
     *
     * @return  int
     */
    public function getAction() {
        return $this->action;
    }

    /**
     * Returns the comment
     *
     * @return  string
     */
    public function getComment() {
        return $this->comment;
    }

    /**
     * Returns the IP address
     *
     * @return  string
     */
    public function getIpAddress() {
        return $this->ipAddress;
    }

    /**
     * Returns the date
     *
     * @return  string
     */
    public function getDate() {
        return $this->date;
    }

    /**
     * Returns an array containing the log's information
     *
     * @return  array
     */
    public function toArray() {
        return array(
            "id" => $this->getId(),
            "userId" => $this->getUserId(),
            "action" => $this->getAction(),
            "comment" => $this->getComment(),
            "ipAddress" => $this->getIpAddress(),
            "date" => date('c', $this->getDate())
        );
    }

    /**
     * Validates the provided action value
     *
     * @param   string  $action
     *
     * @throws  Exception
     */
    public static function validateAction($action) {
        $strlen = strlen($action);

        if($strlen == 0) {
            throw new \Exception("log_action_empty");
        }

        if($strlen > 45) {
            throw new \Exception("log_action_long");
        }
    }

    /**
     * Validates the provided comment
     *
     * @param   string  $comment
     *
     * @throws  Exception
     */
    public static function validateComment($comment) {
        if(strlen($comment) > 100) {
            throw new \Exception("log_comment_long");
        }
    }

    /**
     * Creates a new log entry
     *
     * @param   int     $userId     User's ID
     * @param   string  $action     Action that was logged
     * @param   string  $comment    Extra information
     * @param   string  $ipAddress  IP address associated with action
     *
     * @return  Log
     *
     * @throws  Exception
     */
    public static function createLog($userId, $action, $comment, $ipAddress) {
        self::validateAction($action);

        $comment = \PHPAuth\Util::sanitizeString($comment);
        self::validateComment($comment);

        return new self(
            null,
            $userId,
            $action,
            $comment,
            $ipAddress,
            time()
        );
    }
}