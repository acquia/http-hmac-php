<?php

namespace Acquia\Hmac;

interface KeyLoaderInterface
{
    /**
     * @param string $id
     *
     * @return \Acquia\Hmac\KeyInterface|false
     * @return Request\RequestInterface
     */
    public function load($id);
}
