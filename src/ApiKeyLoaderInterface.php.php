<?php

namespace Acquia\Hmac;

interface ApiKeyLoaderInterface
{
    /**
     * @param string $id
     *
     * @return \Acquia\Hmac\ApiKeyInterface
     */
    public function load($id);
}
