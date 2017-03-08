<?php declare(strict_types = 1);

namespace JDR\JWT;

use Carbon\Carbon;
use Exception;
use Lcobucci\JWT\Token;

class InvalidToken extends Exception
{
    const PARSE_ERROR = 100;
    const INVALID_SIGNATURE = 101;
    const TOKEN_EXPIRED = 102;
    const VALIDATION_FAILED = 103;

    public static function create(string $message, int $code)
    {
        return new static(sprintf('Invalid JSON Web Token: %s', $message), $code);
    }

    public static function parseError(string $message)
    {
        return static::create($message, static::PARSE_ERROR);
    }

    public static function invalidSignature()
    {
        return static::create('The token signature does not match the payload.', static::INVALID_SIGNATURE);
    }

    public static function tokenExpired(Token $token)
    {
        $diff = Carbon::createFromTimestamp($token->getClaim('exp'))->diffForHumans();

        return static::create(sprintf('The token expired %s.', $diff), static::TOKEN_EXPIRED);
    }

    public static function validationFailed()
    {
        return static::create('The token\'s claims could not be validated.', static::VALIDATION_FAILED);
    }
}
