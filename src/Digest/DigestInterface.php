<?php

namespace Acquia\Hmac\Digest;

use Acquia\Hmac\RequestSignerInterface;
use Psr\Http\Message\RequestInterface;

interface DigestInterface
{
    /**
     * Returns the signature.
     *
     * @param \Acquia\Hmac\RequestSignerInterface $requestSigner
     * @param \Psr\Http\Message\RequestInterface $request
     * @param string $secretKey
     *
     * @return string
     */
    public function get(RequestSignerInterface $requestSigner, RequestInterface $request, $secretKey);
}
