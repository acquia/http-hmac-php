<?php

namespace Acquia\Hmac;

interface KeyInterface
{
    /**
     * Returns the key's identifier.
     *
     * @return string
     */
    public function getId();

    /**
     * Returns the key's secret.
     *
     * @return string
     */
    public function getSecret();
}
