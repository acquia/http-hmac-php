<?php

namespace Acquia\Hmac;

use Psr\Http\Message\ResponseInterface;

/**
 * Defines a response signer.
 */
interface ResponseSignerInterface
{
    /**
     * Signs a response with the appropriate headers.
     *
     * @param \Psr\Http\Message\ResponseInterface $response
     *   The response to sign.
     *
     * @return \Psr\Http\Message\ResponseInterface $response
     *   The signed response.
     */
    public function signResponse(ResponseInterface $response);
}
