<?php

class UserTest extends PHPUnit_Framework_TestCase
{
    const EMAIL_EMPTY = '';
    const EMAIL_SHORT = 'a@b';
    const EMAIL_LONG = 'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz@email.com';
    const EMAIL_INVALID = 'invalid email';
    const EMAIL_VALID = 'correct@email.com';
    const EMAIL_INCORRECT = 'incorrect@email.com';

    const PASSWORD_EMPTY = '';
    const PASSWORD_SHORT = '1234';
    const PASSWORD_LONG = 'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz';
    const PASSWORD_WEAK = 'password1';
    const PASSWORD_VALID = 'battery h0rse ST@PLE tr1gg3red';
    const PASSWORD_VALID_2 = 'battery h0rse ST@PLE tr1gg3r';
    const PASSWORD_INCORRECT = 'Inc0rrecT P@$$W0Rd GO3$ HeRe';
    const PASSWORD_HASH = '$2y$10$MgJvUccl/OBHjtmNCeOqWOUh.w0K0uR5t.u7loZLuvvMfZCJpW98a';

    const USER_ID = 57;

    public function testGetEmail()
    {
        $user = new \PHPAuth\User(self::USER_ID, self::EMAIL_VALID, self::PASSWORD_HASH, true);

        $this->assertEquals(self::EMAIL_VALID, $user->getEmail());
    }

    public function testGetId()
    {
        $user = new \PHPAuth\User(self::USER_ID, self::EMAIL_VALID, self::PASSWORD_HASH, true);

        $this->assertEquals(self::USER_ID, $user->getId());
    }

    /**
     * @expectedException			Exception
     * @expectedExceptionMessage	email_empty
     */
    public function testValidateEmailEmpty()
    {
        \PHPAuth\User::validateEmail(self::EMAIL_EMPTY);
    }

    /**
     * @expectedException			Exception
     * @expectedExceptionMessage	email_short
     */
    public function testValidateEmailShort()
    {
        \PHPAuth\User::validateEmail(self::EMAIL_SHORT);
    }

    /**
     * @expectedException			Exception
     * @expectedExceptionMessage	email_long
     */
    public function testValidateEmailLong()
    {
        \PHPAuth\User::validateEmail(self::EMAIL_LONG);
    }

    /**
     * @expectedException			Exception
     * @expectedExceptionMessage	email_invalid
     */
    public function testValidateEmailInvalid()
    {
        \PHPAuth\User::validateEmail(self::EMAIL_INVALID);
    }

    public function testValidateEmail()
    {
        $this->assertEquals(null, \PHPAuth\User::validateEmail(self::EMAIL_VALID));
    }

    /**
     * @expectedException			Exception
     * @expectedExceptionMessage	password_empty
     */
    public function testValidatePasswordEmpty()
    {
        \PHPAuth\User::validatePassword(self::PASSWORD_EMPTY);
    }

    /**
     * @expectedException			Exception
     * @expectedExceptionMessage	password_short
     */
    public function testValidatePasswordShort()
    {
        \PHPAuth\User::validatePassword(self::PASSWORD_SHORT);
    }

    /**
     * @expectedException			Exception
     * @expectedExceptionMessage	password_long
     */
    public function testValidatePasswordLong()
    {
        \PHPAuth\User::validatePassword(self::PASSWORD_LONG);
    }

    public function testValidatePassword()
    {
       $this->assertNull(\PHPAuth\User::validatePassword(self::PASSWORD_VALID));
    }

    /**
     * @expectedException			Exception
     * @expectedExceptionMessage	password_weak
     */
    public function testValidatePasswordStrengthWeak()
    {
        \PHPAuth\User::validatePasswordStrength(self::PASSWORD_WEAK);
    }

    public function testValidatePasswordStrength()
    {
        $this->assertNull(\PHPAuth\User::validatePasswordStrength(self::PASSWORD_VALID));
    }

    

    /**
     * @expectedException			Exception
     * @expectedExceptionMessage	password_incorrect
     */
    public function testVerifyPasswordIncorrect()
    {
        $password = \PHPAuth\User::hashPassword(self::PASSWORD_VALID);

        $user = new \PHPAuth\User(self::USER_ID, self::EMAIL_VALID, self::PASSWORD_VALID, true);
        $this->assertFalse($user->verifyPassword(self::PASSWORD_VALID_2));
    }

    public function testVerifyPassword()
    {
        $password = \PHPAuth\User::hashPassword(self::PASSWORD_VALID);

        $user = new \PHPAuth\User(self::USER_ID, self::EMAIL_VALID, $password, true);
        $this->assertTrue($user->verifyPassword(self::PASSWORD_VALID));
    }
}
