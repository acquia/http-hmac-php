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
}
