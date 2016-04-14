<?php

namespace Acquia\Hmac;

use Psr\Http\Message\ResponseInterface;

/**
 * Defines a response authenticator.
 */
interface ResponseAuthenticatorInterface
{
    /**
     * Authenticates a response according to the HTTP HMAC spec.
     *
     * @param \Psr\Http\Message\ResponseInterface $response
     *   The response to authenticate.
     *
     * @return boolean
     *   True if the response is authentic, false otherwise.
     */
    public function isAuthentic(ResponseInterface $response);
}
