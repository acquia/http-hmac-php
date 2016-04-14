<?php

namespace Acquia\Hmac;

use Psr\Http\Message\RequestInterface;

interface RequestAuthenticatorInterface
{
    /**
     * Authenticates the passed request.
     *
     * @param \Psr\Http\Message\RequestInterface $request
     *
     * @throws \Acquia\Hmac\Exception\InvalidSignatureException
     *   When the signature in the request does not match what's calculated.
     * @throws \Acquia\Hmac\Exception\TimestampOutOfRangeException
     *   When the request timestamp is out of range of the server time.
     * @throws \Acquia\Hmac\Exception\KeyNotFoundException
     *   When the key loader cannot find the key for the request ID.
     *
     * @return \Acquia\Hmac\KeyInterface
     *   The key associated with the ID specified in the request.
     */
    public function authenticate(RequestInterface $request);
}
