<?php

namespace Acquia\Hmac\Digest;

use Acquia\Hmac\Request\RequestInterface;

interface DigestInterface
{
    /**
     * Returns the signature.
     *
     * @param Acquia\Hmac\Request\RequestInterface $request
     * @param string $secretKey
     * @param array $timestampHeaders
     * @param array $customHeaders
     *
     * @return string
     */
    public function get(RequestInterface $request, $secretKey, array $timestampHeaders, array $customHeaders);
}
