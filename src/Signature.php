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
     */
    public function __construct($id, $signature)
    {
        $this->id        = $id;
        $this->signature = $signature;
    }

    /**
     * {@inheritDoc}
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * {@inheritDoc}
     */
    public function getSignature()
    {
        return $this->signature;
    }

    /**
     * {@inheritDoc}
     */
    public function matches($signature)
    {
        return $this->signature === $signature;
    }
}
