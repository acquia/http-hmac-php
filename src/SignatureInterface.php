<?php

namespace Acquia\Hmac;

interface SignatureInterface
{
    /**
     * @return string
     */
    public function getId();

    /**
     * Returns the signature.
     *
     * @return string
     */
    public function getSignature();

    /**
     * Returns true if the signature matches the passed string
     *
     * @param string $signature
     *
     * @return bool
     */
    public function matches($signature);
}
