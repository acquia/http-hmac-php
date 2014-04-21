<?php

namespace Acquia\Hmac;

interface RequestSignerInterface
{
    /**
     * Generates a signature for the request given the secret key and algorithm.
     *
     * @param \Acquia\Hmac\Request\RequestInterface $request
     * @param string $secretKey
     * @param string|null $algorithm
     *
     * @return string
     */
    public function signRequest(Request\RequestInterface $request, $secretKey, $algorithm = null);

    /**
     * Gets the signature passed through the HTTP request.
     *
     * @param \Acquia\Hmac\Request\RequestInterface $request
     *
     * @return \Acquia\Hmac\SignatureInterface
     */
    public function getSignature(Request\RequestInterface $request);
}
