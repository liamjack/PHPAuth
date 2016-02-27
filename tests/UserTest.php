<?php

class UserTest extends PHPUnit_Framework_TestCase {
	public function testGetEmail() {
		$user = new \PHPAuth\User("test@email.com", '$2y$10$MgJvUccl/OBHjtmNCeOqWOUh.w0K0uR5t.u7loZLuvvMfZCJpW98a');

		$this->assertEquals("test@email.com", $user->getEmail());
	}

	public function testGetId() {
		$user = new \PHPAuth\User("test@email.com", '$2y$10$MgJvUccl/OBHjtmNCeOqWOUh.w0K0uR5t.u7loZLuvvMfZCJpW98a', 59);

		$this->assertEquals(59, $user->getId());
	}

	/**
	 * @expectedException			Exception
	 * @expectedExceptionMessage	email_empty
	 */
	public function testValidateEmailEmpty() {
		\PHPAuth\User::validateEmail("");
	}

	/**
	 * @expectedException			Exception
	 * @expectedExceptionMessage	email_short
	 */
	public function testValidateEmailShort() {
		\PHPAuth\User::validateEmail("a@b");
	}

	/**
	 * @expectedException			Exception
	 * @expectedExceptionMessage	email_long
	 */
	public function testValidateEmailLong() {
		\PHPAuth\User::validateEmail(
			"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz@email.com"
		);
	}

	/**
	 * @expectedException			Exception
	 * @expectedExceptionMessage	email_invalid
	 */
	public function testValidateEmailInvalid() {
		\PHPAuth\User::validateEmail("notAnEmail");
	}

	public function testValidateEmail() {
		$this->assertEquals(NULL, \PHPAuth\User::validateEmail("test@email.com"));
	}

	/**
	 * @expectedException			Exception
	 * @expectedExceptionMessage	password_empty
	 */
	public function testValidatePasswordEmpty() {
		\PHPAuth\User::validatePassword("");
	}

	/**
	 * @expectedException			Exception
	 * @expectedExceptionMessage	password_short
	 */
	public function testValidatePasswordShort() {
		\PHPAuth\User::validatePassword("abcde");
	}

	/**
	 * @expectedException			Exception
	 * @expectedExceptionMessage	password_long
	 */
	public function testValidatePasswordLong() {
		\PHPAuth\User::validatePassword(
			"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz"
		);
	}

	/**
	 * @expectedException			Exception
	 * @expectedExceptionMessage	password_weak
	 */
	public function testValidatePasswordWeak() {
		\PHPAuth\User::validatePassword("abcdefghijklmnop");
	}

	public function testValidatePassword() {
		\PHPAuth\User::validatePassword('tH1$ 1$ @ $3CUR3 P@$$W0Rd');
	}

	/**
	 * @expectedException			Exception
	 * @expectedExceptionMessage	password_incorrect
	 */
	public function testVerifyPasswordIncorrect() {
		$password = \PHPAuth\User::hashPassword("testPassword");

		$user = new \PHPAuth\User("test@email.com", $password);
		$user->verifyPassword("notTestPassword");
	}

	public function testVerifyPassword() {
		$password = \PHPAuth\User::hashPassword("testPassword");

		$user = new \PHPAuth\User("test@email.com", $password);
		$this->assertEquals(NULL, $user->verifyPassword("testPassword"));
	}
}