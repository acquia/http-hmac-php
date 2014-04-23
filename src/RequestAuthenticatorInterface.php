<?php

namespace Acquia\Hmac;

interface RequestAuthenticatorInterface
{
    /**
     * Authenticates the passed request.
     *
     * @param \Acquia\Hmac\Request\RequestInterface $request
     *
     * @return true
     *
     * @throws \Acquia\Hmac\Exception\InvalidRequest
     */
    public function authenticate(Request\RequestInterface $request);
}
