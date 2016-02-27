<?php

class PHPAuthTest extends PHPUnit_Framework_TestCase {
	
	const TEST_IP_ADDRESS = '127.0.0.1';
	const TEST_USER_AGENT = 'PHPUnit';

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

	private $database;
	private $phpauth;

	public function __construct() {
		$this->database = new \PHPAuth\Database\MySQL("localhost", "root", "root", "phpauth_db");
		$this->phpauth = new \PHPAuth\PHPAuth($this->database);

		$_SERVER['REMOTE_ADDR'] = self::TEST_IP_ADDRESS;
		$_SERVER['HTTP_USER_AGENT'] = self::TEST_USER_AGENT;
	}

	/**
	 * @expectedException			Exception
	 * @expectedExceptionMessage	email_empty
	 */

	public function testLoginEmailEmpty() {
		$this->phpauth->login(self::EMAIL_EMPTY, self::PASSWORD_VALID);
	}

	/**
	 * @expectedException			Exception
	 * @expectedExceptionMessage	email_short
	 */

	public function testLoginEmailShort() {
		$this->phpauth->login(self::EMAIL_SHORT, self::PASSWORD_VALID);
	}

	/**
	 * @expectedException			Exception
	 * @expectedExceptionMessage	email_long
	 */

	public function testLoginEmailLong() {
		$this->phpauth->login(self::EMAIL_LONG, self::PASSWORD_VALID);
	}

	/**
	 * @expectedException			Exception
	 * @expectedExceptionMessage	email_invalid
	 */

	public function testLoginEmailInvalid() {
		$this->phpauth->login(self::EMAIL_INVALID, self::PASSWORD_VALID);
	}

	/**
	 * @expectedException			Exception
	 * @expectedExceptionMessage	email_password_incorrect
	 */

	public function testLoginEmailIncorrect() {
		$this->phpauth->login(self::EMAIL_INCORRECT, self::PASSWORD_VALID);
	}

	/**
	 * @expectedException			Exception
	 * @expectedExceptionMessage	password_empty
	 */

	public function testLoginPasswordEmpty() {
		$this->phpauth->login(self::EMAIL_VALID, self::PASSWORD_EMPTY);
	}

	/**
	 * @expectedException			Exception
	 * @expectedExceptionMessage	password_short
	 */

	public function testLoginPasswordShort() {
		$this->phpauth->login(self::EMAIL_VALID, self::PASSWORD_SHORT);
	}

	/**
	 * @expectedException			Exception
	 * @expectedExceptionMessage	password_long
	 */

	public function testLoginPasswordLong() {
		$this->phpauth->login(self::EMAIL_VALID, self::PASSWORD_LONG);
	}

	/**
	 * @expectedException			Exception
	 * @expectedExceptionMessage	password_weak
	 */

	public function testLoginPasswordWeak() {
		$this->phpauth->login(self::EMAIL_VALID, self::PASSWORD_WEAK);
	}

	/**
	 * @expectedException			Exception
	 * @expectedExceptionMessage	email_password_incorrect
	 */

	public function testLoginPasswordIncorrect() {
		$this->phpauth->login(self::EMAIL_VALID, self::PASSWORD_INCORRECT);
	}

	public function testLogin() {
		$session = $this->phpauth->login(self::EMAIL_VALID, self::PASSWORD_VALID);

		$this->assertEquals(self::TEST_USER_AGENT, $session->getUserAgent());
	}
	

	/**
	 * @expectedException			Exception
	 * @expectedExceptionMessage	email_empty
	 */

	public function testRegisterEmailEmpty() {
		$this->phpauth->register(self::EMAIL_EMPTY, self::PASSWORD_VALID, self::PASSWORD_VALID);
	}

	/**
	 * @expectedException			Exception
	 * @expectedExceptionMessage	email_short
	 */

	public function testRegisterEmailShort() {
		$this->phpauth->register(self::EMAIL_SHORT, self::PASSWORD_VALID, self::PASSWORD_VALID);
	}

	/**
	 * @expectedException			Exception
	 * @expectedExceptionMessage	email_long
	 */

	public function testRegisterEmailLong() {
		$this->phpauth->register(self::EMAIL_LONG, self::PASSWORD_VALID, self::PASSWORD_VALID);
	}

	/**
	 * @expectedException			Exception
	 * @expectedExceptionMessage	email_invalid
	 */

	public function testRegisterEmailInvalid() {
		$this->phpauth->register(self::EMAIL_INVALID, self::PASSWORD_VALID, self::PASSWORD_VALID);
	}

	/**
	 * @expectedException			Exception
	 * @expectedExceptionMessage	email_used
	 */

	public function testRegisterEmailUsed() {
		$this->phpauth->register(self::EMAIL_VALID, self::PASSWORD_VALID, self::PASSWORD_VALID);
	}

	/**
	 * @expectedException			Exception
	 * @expectedExceptionMessage	password_empty
	 */

	public function testRegisterPasswordEmpty() {
		$this->phpauth->register(self::EMAIL_VALID, self::PASSWORD_EMPTY, self::PASSWORD_EMPTY);
	}

	/**
	 * @expectedException			Exception
	 * @expectedExceptionMessage	password_short
	 */

	public function testRegisterPasswordShort() {
		$this->phpauth->register(self::EMAIL_VALID, self::PASSWORD_SHORT, self::PASSWORD_SHORT);
	}

	/**
	 * @expectedException			Exception
	 * @expectedExceptionMessage	password_long
	 */

	public function testRegisterPasswordLong() {
		$this->phpauth->register(self::EMAIL_VALID, self::PASSWORD_LONG, self::PASSWORD_LONG);
	}

	/**
	 * @expectedException			Exception
	 * @expectedExceptionMessage	password_weak
	 */

	public function testRegisterPasswordWeak() {
		$this->phpauth->register(self::EMAIL_VALID, self::PASSWORD_WEAK, self::PASSWORD_WEAK);
	}

	/**
	 * @expectedException			Exception
	 * @expectedExceptionMessage	password_no_match
	 */

	public function testRegisterPasswordNoMatch() {
		$this->phpauth->register(self::EMAIL_VALID, self::PASSWORD_VALID, self::PASSWORD_VALID_2);
	}

	public function testIsSessionValid() {
		$session = $this->phpauth->login(self::EMAIL_VALID, self::PASSWORD_VALID);

		$this->assertTrue($this->phpauth->isSessionValid($session->getUuid()));
	}

	
}