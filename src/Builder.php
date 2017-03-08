<?php declare(strict_types = 1);

namespace JDR\JWT;

use Lcobucci\JWT\Builder as JWTBuilder;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;

class Builder
{
    /**
     * @var Signer
     */
    private $signer;

    /**
     * @var Key
     */
    private $privateKey;

    /**
     * @var string[]
     */
    private $options;

    public function __construct(Signer $signer, Key $privateKey, array $options = null)
    {
        $this->signer = $signer;
        $this->privateKey = $privateKey;
        $this->options = $options;
    }

    public function build(array $claims = []): Token
    {
        $builder = new JWTBuilder();

        if (isset($this->options['issuer'])) {
            $builder->setIssuer($this->options['issuer']);
        }
        if (isset($this->options['audience'])) {
            $builder->setAudience($this->options['audience']);
        }

        $builder->setIssuedAt(time());
        if (isset($this->options['lifetime'])) {
            $builder->setExpiration(time() + $this->options['lifetime']);
        }

        foreach ($claims as $claim => $value) {
            $builder->set($claim, $value);
        }

        return $builder
            ->sign($this->signer, $this->privateKey)
            ->getToken();
    }
}
