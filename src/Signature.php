<?php

namespace Acquia\Hmac;

class Signature implements SignatureInterface
{
    /**
     * @var string
     */
    protected $id;

    /**
     * @var string
     */
    protected $signature;

    /**
     * @param string $id
     * @param string $signature
     * @param string $provider
     */
    public function __construct($id, $signature)
    {
        $this->apiKeyId  = $id;
        $this->signature = $signature;
    }

    /**
     * @return string
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * @return string
     */
    public function getSignature()
    {
        return $this->signature;
    }

    /**
     * @return string
     */
    public function __toString()
    {
        return $this->signature;
    }
}
