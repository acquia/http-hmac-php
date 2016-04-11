<?php

namespace Acquia\Hmac\Test\Mocks;

use Acquia\Hmac\AuthorizationHeaderInterface;
use Acquia\Hmac\Digest\DigestInterface;
use Acquia\Hmac\KeyInterface;
use Acquia\Hmac\RequestSigner;
use Psr\Http\Message\RequestInterface;

/**
 * Allows the signing of requests with a custom authorization header.
 */
class MockRequestSigner extends RequestSigner
{
    /**
     * @var \Acquia\Hmac\AuthorizationHeaderInterface
     *  A custom authorization header.
     */
    protected $authHeader;

    /**
     * Initializes the request signer with a key, realm, and auth header.
     *
     * @param \Acquia\Hmac\KeyInterface $key
     *   The key to sign requests with.
     * @param string $realm
     *   The API realm/provider
     * @param \Acquia\Hmac\Digest\DigestInterface $digest
     *   The message digest to use when signing requests.
     * @param \Acquia\Hmac\AuthorizationHeaderInterface $authHeader
     *   The custom authorization header.
     */
    public function __construct(KeyInterface $key, $realm, DigestInterface $digest, AuthorizationHeaderInterface $authHeader)
    {
        parent::__construct($key, $realm, $digest);

        $this->authHeader = $authHeader;
    }

    /**
     * {@inheritDoc}
     */
    protected function buildAuthorizationHeader(RequestInterface $request, array $customHeaders = [])
    {
        return $this->authHeader;
    }
}
