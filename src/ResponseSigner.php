<?php

namespace Acquia\Hmac;

use Acquia\Hmac\Digest\Digest;
use Acquia\Hmac\Digest\DigestInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Signs responses according to the HTTP HMAC spec.
 */
class ResponseSigner
{
    /**
     * @var \Acquia\Hmac\KeyInterface
     *   The key with which to sign the response.
     */
    protected $key;

    /**
     * @var \Psr\Http\Message\RequestInterface
     *   The original response corresponding to the response being signed.
     */
    protected $request;

    /**
     * @var \Acquia\Hmac\Digest\DigestInterface
     *   The digest with which to sign the response.
     */
    protected $digest;
    /**
     * Initializes the response signer with a key and request.
     *
     * @param \Acquia\Hmac\KeyInterface $key
     *   The key with which to sign the response.
     * @param \Psr\Http\Message\RequestInterface $request
     *   The original response corresponding to the response being signed.
     * @param \Acquia\Hmac\Digest\Digest $digest
     *   The digest with which to sign the response. Defaults to
     *   \Acquia\Hmac\Digest\Digest.
     */
    public function __construct(KeyInterface $key, RequestInterface $request, DigestInterface $digest = null)
    {
        $this->key = $key;
        $this->request = $request;
        $this->digest = $digest ?: new Digest();
    }

    /**
     * {@inheritDoc}
     */
    public function signResponse(ResponseInterface $response)
    {
        $authHeader = AuthorizationHeader::createFromRequest($this->request);

        $parts = [
            $authHeader->getNonce(),
            $this->request->getHeaderLine('X-Authorization-Timestamp'),
            (string) $response->getBody(),
        ];

        $response->getBody()->rewind();

        $message = implode("\n", $parts);

        $signature = $this->digest->sign($message, $this->key->getSecret());

        /** @var \Psr\Http\Message\ResponseInterface $response */
        $response = $response->withHeader('X-Server-Authorization-HMAC-SHA256', $signature);

        return $response;
    }
}
