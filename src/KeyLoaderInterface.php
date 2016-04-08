<?php

namespace Acquia\Hmac;

interface KeyLoaderInterface
{
    /**
     * @param string $id
     *
     * @return \Acquia\Hmac\KeyInterface|false
     */
    public function load($id);

    /**
     * Adds a key to the loader.
     *
     * @param string $id
     * @param string $secret
     */
    public function addKey($id, $secret);
}
