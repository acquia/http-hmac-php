<?php

namespace Acquia\Hmac;

interface RequestAuthenticatorInterface
{
    /**
     * Authenticates the passed request.
     *
     * @param \Acquia\Hmac\Request\RequestInterface $request
     * @param \Acquia\Hmac\KeyLoaderInterface $keyLoader
     *
     * @return \Acquia\Hmac\KeyInterface
     *
     * @throws \Acquia\Hmac\Exception\InvalidRequestException
     */
    public function authenticate(Request\RequestInterface $request, KeyLoaderInterface $keyLoader);
}
