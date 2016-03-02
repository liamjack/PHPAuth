<?php

namespace PHPAuth;

/**
 * @author Liam Jack <cuonic@cuonic.com>
 * @license MIT
 */
class User
{
    private $id;
    private $email;
    private $password;
    private $password_hash;

    /**
     * @param int    $id       User ID in database
     * @param string $email    User's email address
     * @param string $password User's hashed password
     */
    public function __construct($id, $email, $password_hash)
    {
        $this->id = $id;
        $this->email = $email;
        $this->password_hash = $password_hash;
    }

    /**
     * Returns the user's ID.
     *
     * @return int
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * Returns the user's email address.
     *
     * @return string
     */
    public function getEmail()
    {
        return $this->email;
    }

    /**
     * Modifies the user's email address.
     *
     * @param string $email User's email address
     */
    private function setEmail($email)
    {
        $this->email = $email;
    }

    /**
     * Returns the user's hashed password.
     *
     * @return string
     */
    public function getPassword()
    {
        return $this->password_hash;
    }

    /**
     * Modifies the user's hashed password.
     *
     * @param string $password User's hashed password
     *
     * @throws Exception
     */
    private function setPassword($password_hash)
    {
        if (strlen($password_hash) != 60) {
            throw new \Exception('system_error');
        }

        $this->password_hash = $password_hash;
    }

    /**
     * Validates an email address.
     *
     * @param string $email
     *
     * @throws Exception
     */
    public static function validateEmail($email)
    {
        if (strlen($email) == 0) {
            throw new \Exception('email_empty');
        }

        if (strlen($email) < Configuration::EMAIL_MINIMUM_LENGTH) {
            throw new \Exception('email_short');
        }

        if (strlen($email) > Configuration::EMAIL_MAXIMUM_LENGTH) {
            throw new \Exception('email_long');
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            throw new \Exception('email_invalid');
        }
    }

    /**
     * Validates a password.
     *
     * @param string $password
     *
     * @throws Exception
     */
    public static function validatePassword($password)
    {
        if (strlen($password) == 0) {
            throw new \Exception('password_empty');
        }

        if (strlen($password) < Configuration::PASSWORD_MINIMUM_LENGTH) {
            throw new \Exception('password_short');
        }

        if (strlen($password) > Configuration::PASSWORD_MAXIMUM_LENGTH) {
            throw new \Exception('password_long');
        }
    }

    /**
     * Check if a password respects the site's password strength requirements.
     *
     * @param string $password
     *
     * @throws Exception
     */
    public static function validatePasswordStrength($password)
    {
        $zxcvbn = new \ZxcvbnPhp\Zxcvbn();
        $score = $zxcvbn->passwordStrength($password)['score'];

        if ($score < Configuration::PASSWORD_MINIMUM_SCORE) {
            throw new \Exception('password_weak');
        }
    }

    /**
     * Changes a user's password.
     *
     * @param string $password          User's current password
     * @param string $newPassword       User's desired new password
     * @param string $repeatNewPassword User's desired new password, repeated to prevent typos
     *
     * @throws Exception
     */
    public function changePassword($password, $newPassword, $repeatNewPassword)
    {
        // Validate current password
        self::validatePassword($password);

        // Validate new password
        self::validatePassword($newPassword);
        self::validatePasswordStrength($newPassword);

        if ($newPassword !== $repeatNewPassword) {
            // New password and confirmation do not match
            throw new \Exception('password_no_match');
        }

        if (!$this->verifyPassword($password)) {
            // User's current password is incorrect
            throw new \Exception('password_incorrect');
        }

        // Hash new password
        $newPasswordHash = self::hashPassword($newPassword);

        // Change password
        $this->setPassword($newPasswordHash);
    }

    /**
     * Changes a user's email address.
     *
     * @param string $password User's password
     * @param string $newEmail User's new email address
     *
     * @throws Exception
     */
    public function changeEmail($password, $newEmail)
    {
        // Validate password
        self::validatePassword($password);

        // Validate email address
        self::validateEmail($newEmail);

        if ($newEmail == $this->getEmail()) {
            // New email address is the same as current email address
            throw new \Exception('email_same');
        }

        if (!$this->verifyPassword($password)) {
            // User's current password is incorrect
            throw new \Exception('password_incorrect');
        }

        // Change email address
        $this->setEmail($newEmail);
    }

    /**
     * Hashes a password.
     *
     * @param string $password
     *
     * @return string
     */
    public static function hashPassword($password)
    {
        return password_hash($password, PASSWORD_BCRYPT, array('cost' => Configuration::PASSWORD_HASH_COST));
    }

    /**
     * Check if a password matches the user's password.
     *
     * @param string $password
     *
     * @return bool
     */
    public function verifyPassword($password)
    {
        return password_verify($password, $this->password_hash);
    }

    /**
     * Returns a new user.
     *
     * @param string $email
     * @param string $password
     *
     * @return User
     */
    public static function createUser($email, $password)
    {
        return new self(null, $email, self::hashPassword($password));
    }
}
