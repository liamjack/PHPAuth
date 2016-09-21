<?php

namespace PHPAuth;

class Util
{
    /**
     * Validates a UUIDv4.
     *
     * @param   string  $sessionUuid UUID
     *
     * @return  boolean
     *
     * @throws  Exception
     */
    public static function validateUuid($uuid)
    {
        if (preg_match('/^([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$/', $uuid) == 1) {
            return true;
        }

        return false;
    }

    /**
     * Generates a random UUIDv4.
     *
     * @return string
     */
    public static function generateUuid()
    {
        return sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            mt_rand(0, 0xffff), mt_rand(0, 0xffff),
            mt_rand(0, 0xffff),
            mt_rand(0, 0x0fff) | 0x4000,
            mt_rand(0, 0x3fff) | 0x8000,
            mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
        );
    }

    /**
     * Sanitizes a string, escaping HTML entities
     *
     * @param   string  $string
     *
     * @return  string
     */
    public static function sanitizeString($string) {
        return htmlentities($string);
    }
}