<?php

namespace Acquia\Hmac;

interface SignatureInterface
{
    /**
     * @return string
     */
    public function getId();

    /**
     * @return string
     */
    public function getSignature();
}
