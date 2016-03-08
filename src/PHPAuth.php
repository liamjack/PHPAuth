<?php

namespace PHPAuth;

/**
 * @author Liam Jack <cuonic@cuonic.com>
 * @license MIT
 */
class PHPAuth
{
    private $database;
    private $isAuthenticated = false;
    private $currentSession = null;
    private $authenticatedUser = null;

    /**
     * Creates a new instance of the class, checking if the current user is authenticated
     * or not.
     *
     * @param Database $database
     */
    public function __construct(Database $database)
    {
        $this->database = $database;

        if (isset($_COOKIE[Configuration::SESSION_COOKIE_NAME])) {
            $sessionUuid = $_COOKIE[Configuration::SESSION_COOKIE_NAME];

            if (!$this->isSessionValid($sessionUuid)) {
                deleteSessionCookie();
            }
        }
    }

    /**
     * Allows a user to authenticate and creates a new session.
     *
     * @param string $email    User's email address
     * @param string $password User's password
     *
     * @return session
     *
     * @throws Exception
     */
    public function login($email, $password, $isPersistent = false)
    {
        if ($this->isAuthenticated()) {
            // User is already authenticated
            throw new \Exception('already_authenticated');
        }

        // Validate email address
        User::validateEmail($email);

        // Validate password
        User::validatePassword($password);

        // Get user with provided email address
        $user = $this->database->getUserByEmail($email);

        if ($user == null) {
            // User does not exist
            throw new \Exception('email_password_incorrect');
        }

        if(!$user->isActivated()) {
            // Account is not yet activated
            throw new \Exception("account_not_activated");
        }

        if (!$user->verifyPassword($password)) {
            // Provided password doesn't match the user's password
            throw new \Exception('email_password_incorrect');
        }

        // Create a new session
        $session = Session::createSession($user->getId(), $isPersistent);

        // Add session to database
        $this->database->addSession($session);

        // Set the user's session cookie
        $this->setSessionCookie($session->getUuid(), $session->getExpiryDate());

        // Set authenticated user
        $this->setAuthenticatedUser($user);
    }

    /**
     * Creates a new user account.
     *
     * @param string $email          User's email address
     * @param string $password       User's desired password
     * @param string $repeatPassword User's desired password, repeated to prevent typos
     *
     * @throws Exception
     */
    public function register($email, $password, $repeatPassword)
    {
        if (!Configuration::REGISTRATION_ENABLED) {
            throw new \Exception('registration_disabled');
        }

        if ($this->isAuthenticated()) {
            // User is already authenticated
            throw new \Exception('already_authenticated');
        }

        // Validate email address
        User::validateEmail($email);

        // Validate password
        User::validatePassword($password);

        // Validate password strength
        User::validatePasswordStrength($password);

        if ($password !== $repeatPassword) {
            // Password and password confirmation do not match
            throw new \Exception('password_no_match');
        }

        if ($this->database->doesUserExistByEmail($email)) {
            // User with this email address already exists
            throw new \Exception('email_used');
        }

        // Create new user
        $user = User::createUser($email, $password);

        // Add user to database
        $this->database->addUser($user);

        if(Configuration::ACCOUNT_ACTIVATION_REQUIRED) {
            // Account activation is required, send activation email
            $this->sendActivationEmail($email);
        }
    }

    /**
     * Changes the authenticated user's password.
     *
     * @param string $password
     * @param string $newPassword
     * @param string $repeatNewPassword
     *
     * @throws Exception
     */
    public function changePassword($password, $newPassword, $repeatNewPassword)
    {
        if (!$this->isAuthenticated()) {
            // User is not authenticated
            throw new \Exception('not_authenticated');
        }

        // Change the user's password
        $this->authenticatedUser->changePassword($password, $newPassword, $repeatNewPassword);

        // Push the change to the database
        $this->database->updateUser($this->authenticatedUser);
    }

    /**
     * Changes the authenticated user's email address.
     *
     * @param string $password
     * @param string $newEmail
     *
     * @throws Exception
     */
    public function changeEmail($password, $newEmail)
    {
        if (!$this->isAuthenticated()) {
            // User is not authenticated
            throw new \Exception('not_authenticated');
        }

        // Change the user's email address
        $this->authenticatedUser->changeEmail($password, $newEmail);

        // Push the change to the database
        $this->database->updateUser($this->authenticatedUser);
    }

    /**
     * Deletes a users account.
     *
     * @param string $password
     *
     * @throws Exception
     */
    public function delete($password)
    {
        if (!$this->isAuthenticated()) {
            // User is not authenticated
            throw new \Exception('not_authenticated');
        }

        // Validate password
        User::validatePassword($password);

        if (!$this->authenticatedUser->verifyPassword($password)) {
            // User's password is incorrect
            throw new \Exception('password_incorrect');
        }

        // Delete the user from the database
        $this->database->deleteUser($this->authenticatedUser->getId());

        // Logout the user
        $this->logout();
    }

    /**
     * Logs the user out.
     */
    public function logout()
    {
        if (!$this->isAuthenticated()) {
            // User is not authenticated
            throw new \Exception('not_authenticated');
        }

        // Delete the user's session from database
        $this->database->deleteSession($this->currentSession->getUuid());

        // Delete user's cookie
        $this->deleteSessionCookie();
    }

    /**
     * Sends an account activation to the provided email address
     *
     * @param   string  $email
     *
     * @throws  Exception
     */
    private function sendActivationEmail($email)
    {
        // Create JWT token

        $signer = new Lcobucci\JWT\Signer\Hmac\Sha256();

        $token = (new Lcobucci\JWT\Builder())->setIssuedAt(time())
                                             ->setExpiration(strtotime(Configuration::ACCOUNT_ACTIVATION_EXPIRY))
                                             ->set('action', 'activate')
                                             ->set('email', $email)
                                             ->sign($signer, Configuration::ACCOUNT_ACTIVATION_SECRET)
                                             ->getToken();

        $body = strreplace(
            '%activation_token%',
            $token,
            file_get_contents(
                Configuration::ACCOUNT_ACTIVATION_BODY_FILE
            )
        );

        $altBody = strreplace(
            '%activation_token%',
            $token,
            file_get_contents(
                Configuration::ACCOUNT_ACTIVATION_ALTBODY_FILE
            )
        );

        // Send to email address
        sendEmail($email, Configuration::ACCOUNT_ACTIVATION_SUBJECT, $body, $altBody);
    }


    /**
     * Sends an email to the provided email address, with the provided subject, body and altBody
     *
     * @param   string  $email
     * @param   string  $subject
     * @param   string  $body
     * @param   string  $altBody
     *
     * @throws  Exception
     */
    private function sendEmail($email, $subject, $body, $altBody)
    {
        $mail = new PHPMailer();

        if(Configuration::MAIL_SMTP) {
            // Email is sent via SMTP

            $mail->isSMTP();

            $mail->Host = Configuration::MAIL_SMTP_HOSTNAME;
            $mail->SMTPSecure = Configuration::MAIL_SMTP_SECURE;
            $mail->Port = Configuration::MAIL_SMTP_PORT;

            if(Configuration::MAIL_SMTP_AUTH) {
                // SMTP authentication is required

                $mail->SMTPAuth = true;
                $mail->Username = Configuration::MAIL_SMTP_USERNAME;
                $mail->Password = Configuration::MAIL_SMTP_PASSWORD;
            }
        }

        $mail->setFrom(Configuration::MAIL_FROM_EMAIL, Configuration::MAIL_FROM_NAME);
        $mail->addAddress($email);
        $mail->isHTML(true);

        $mail->Subject = $subject;
        $mail->Body = $body;
        $mail->AltBody = $altBody;

        if(!$mail->send()) {
            throw new \Exception("mail_error");
        }
    }

    /**
     * Checks whether a user's session is valid or not and performs
     * modifications / deletions of sessions when necessary.
     *
     * @param string $sessionUuid The session's UUID
     *
     * @return bool
     */
    public function isSessionValid($sessionUuid)
    {
        if ($this->isAuthenticated()) {
            // Session already validated
            return true;
        }

        // Validate the session's UUID
        if (!Session::validateUuid($sessionUuid)) {
            return false;
        }

        // Fetch the session from the database
        $this->currentSession = $this->database->getSession($sessionUuid);

        if ($this->currentSession == null) {
            // Session doesn't exist
            return false;
        }

        if (!$this->currentSession->isValid()) {
            // Session is invalid, delete
            $this->database->deleteSession($sessionUuid);

            return false;
        }

        if ($this->currentSession->isUpdateRequired()) {
            // Session has been updated during verification, push update to database
            $this->database->updateSession($this->currentSession);
        }

        // Session is valid, set authenticated user
        $this->setAuthenticatedUserById($this->currentSession->getUserId());

        return true;
    }

    /**
     * Indicates if the user is authenticated.
     *
     * @return bool
     */
    public function isAuthenticated()
    {
        return $this->isAuthenticated;
    }

    /**
     * Returns the currently authenticated user, or NULL if no user is not authenticated.
     *
     * @return User
     */
    public function getAuthenticatedUser()
    {
        return $this->authenticatedUser;
    }

    /**
     * Sets the currently authenticated user.
     *
     * @param User $user
     */
    private function setAuthenticatedUser(User $user)
    {
        $this->authenticatedUser = $user;
        $this->isAuthenticated = true;
    }

    /**
     * Sets the currently authenticated user by User ID, fetching the user from database.
     *
     * @param int $userId
     */
    private function setAuthenticatedUserById($userId)
    {
        $this->authenticatedUser = $this->database->getUserById($userId);

        if ($this->authenticatedUser == null) {
            // User doesn't exist
            $this->isAuthenticated = false;
        } else {
            $this->isAuthenticated = true;
        }
    }

    /**
     * Returns the current session.
     *
     * @return Session
     */
    public function getCurrentSession()
    {
        return $this->currentSession;
    }

    /**
     * Sets the user's session cookie.
     *
     * @param string $sessionUuid
     * @param int    $expiryDate
     */
    public function setSessionCookie($sessionUuid, $expiryDate)
    {
        setcookie(
            Configuration::SESSION_COOKIE_NAME,
            $sessionUuid,
            $expiryDate,
            Configuration::SESSION_COOKIE_PATH,
            Configuration::SESSION_COOKIE_DOMAIN,
            Configuration::SESSION_COOKIE_SECURE,
            Configuration::SESSION_COOKIE_HTTPONLY
        );
    }

    /**
     * Deletes the user's session cookie.
     */
    public function deleteSessionCookie()
    {
        unset($_COOKIE[Configuration::SESSION_COOKIE_NAME]);
        setSessionCookie(null, time() - 3600);
    }
}
