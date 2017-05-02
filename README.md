# PHPAuth

## About

PHP 7 compatible library for authenticating users using session cookies.

## Features

  * Login
  * Sign up
  * Change email address
  * Change password
  * Delete account
  * View active sessions
  * Revoke active session
  * View security logs
  * Logout

## Requirements

* `>= php v7.0`

## Installation

`composer require liamjack/phpauth:dev-master`

## Usage

```
require_once('vendor/autoload.php');

$database = new \PHPAuth\Database\MySQL(
    $db_host,
    $db_user,
    $db_pass,
    $db_name
);

$phpauth = new \PHPAuth\PHPAuth($database);
```

## See also

  * [PHPAuth-API](https://github.com/liamjack/PHPAuth-API)
  A simple REST API layer on top of PHPAuth