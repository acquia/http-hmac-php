<?php

namespace Acquia\Hmac;

interface KeyLoaderInterface
{
    /**
     * @param string $id
     *
     * @return \Acquia\Hmac\KeyInterface
     */
    public function load($id);
}
