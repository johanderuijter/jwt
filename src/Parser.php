<?php declare(strict_types = 1);

namespace JDR\JWT;

use Lcobucci\JWT\Parser as JWTParser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;
use Throwable;

class Parser
{
    /**
     * @var Signer
     */
    private $signer;

    /**
     * @var Key
     */
    private $publicKey;

    /**
     * @var string[]
     */
    private $options;

    public function __construct(Signer $signer, Key $publicKey, array $options = [])
    {
        $this->signer = $signer;
        $this->publicKey = $publicKey;
        $this->options = $options;
    }

    /**
     * @throws InvalidToken When the token is invalid.
     */
    public function parse(string $tokenString): Token
    {
        try {
            $parser = new JWTParser();
            $token = $parser->parse($tokenString);
        } catch (Throwable $exception) {
            throw InvalidToken::parseError($exception->getMessage());
        }

        if (!$token->verify($this->signer, $this->publicKey)) {
            throw InvalidToken::invalidSignature();
        }

        if ($token->isExpired()) {
            throw InvalidToken::tokenExpired($token);
        }

        if (!$token->validate($this->getValidationData($this->options))) {
            throw InvalidToken::validationFailed();
        }

        return $token;
    }

    private function getValidationData(array $options = []): ValidationData
    {
        $validationData = new ValidationData();
        if (isset($options['issuer'])) {
            $validationData->setIssuer($options['issuer']);
        }
        if (isset($options['audience'])) {
            $validationData->setAudience($options['audience']);
        }

        return $validationData;
    }
}
