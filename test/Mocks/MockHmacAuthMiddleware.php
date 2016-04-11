<?php

namespace Acquia\Hmac\Test\Mocks;

use Acquia\Hmac\AuthorizationHeader;
use Acquia\Hmac\Digest\Digest;
use Acquia\Hmac\Guzzle\HmacAuthMiddleware;
use Acquia\Hmac\KeyInterface;

/**
 * Allows the signing of requests with a custom authorization header.
 */
class MockHmacAuthMiddleware extends HmacAuthMiddleware
{
    /**
     * Initializes the middleware with a key, realm, and custom auth header.
     *
     * @param \Acquia\Hmac\KeyInterface $key
     *   The key to sign requests with.
     * @param string $realm
     *   The API realm/provider.
     * @param \Acquia\Hmac\AuthorizationHeaderInterface $authHeader
     *   The custom authorization header.
     */
    public function __construct(KeyInterface $key, $realm, AuthorizationHeader $authHeader)
    {
        parent::__construct($key, $realm);

        $this->requestSigner = new MockRequestSigner($key, $realm, new Digest(), $authHeader);
    }
}
