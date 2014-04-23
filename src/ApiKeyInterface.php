<?php

namespace Acquia\Hmac;

interface ApiKeyInterface
{
    /**
     * Returns the API key's identifier.
     *
     * @return string
     */
    public function getId();

    /**
     * Returns the API Key's secret.
     *
     * @return string
     */
    public function getSecret();
}
