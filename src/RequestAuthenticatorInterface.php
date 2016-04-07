<?php

namespace Acquia\Hmac;

use Psr\Http\Message\RequestInterface;

interface RequestAuthenticatorInterface
{
    /**
     * Authenticates the passed request.
     *
     * @param \Psr\Http\Message\RequestInterface $request
     * @param \Acquia\Hmac\KeyLoaderInterface $keyLoader
     *
     * @return \Acquia\Hmac\KeyInterface
     *
     * @throws \Acquia\Hmac\Exception\InvalidRequestException
     */
    public function authenticate(RequestInterface $request, KeyLoaderInterface $keyLoader);
}
