<?php

namespace Acquia\Hmac;

use Acquia\Hmac\Digest\Digest;
use Acquia\Hmac\Digest\DigestInterface;
use Psr\Http\Message\RequestInterface;

/**
 * Signs requests according to the HTTP HMAC spec.
 */
class RequestSigner implements RequestSignerInterface
{
    /**
     * @var \Acquia\Hmac\KeyInterface
     *   The key to sign requests with.
     */
    protected $key;

    /**
     * @var string
     *   The API realm/provider.
     */
    protected $realm;

    /**
     * @var \Acquia\Hmac\Digest\DigestInterface
     *   The message digest to use when signing requests.
     */
    protected $digest;

    /**
     * Initializes the request signer with a key and realm.
     *
     * @param \Acquia\Hmac\KeyInterface $key
     *   The key to sign requests with.
     * @param string $realm
     *   The API realm/provider. Defaults to "Acquia".
     * @param \Acquia\Hmac\Digest\DigestInterface $digest
     *   The message digest to use when signing requests. Defaults to
     *   \Acquia\Hmac\Digest\Digest.
     */
    public function __construct(KeyInterface $key, $realm = 'Acquia', DigestInterface $digest = null)
    {
        $this->key = $key;
        $this->realm = $realm;
        $this->digest = $digest ?: new Digest();
    }

    /**
     * {@inheritDoc}
     */
    public function signRequest(RequestInterface $request, array $customHeaders = [])
    {
        $request = $this->getTimestampedRequest($request);
        $request = $this->getContentHashedRequest($request);
        $request = $this->getAuthorizedRequest($request, $customHeaders);

        return $request;
    }

    /**
     * {@inheritDoc}
     */
    public function getTimestampedRequest(RequestInterface $request, \DateTime $date = null)
    {
        if ($request->hasHeader('X-Authorization-Timestamp')) {
            return clone $request;
        }

        $date = $date ?: new \DateTime('now', new \DateTimeZone('UTC'));

        /** @var RequestInterface $request */
        $request = $request->withHeader('X-Authorization-Timestamp', (string) $date->getTimestamp());

        return $request;
    }

    /**
     * {@inheritDoc}
     */
    public function getContentHashedRequest(RequestInterface $request)
    {
        $body = (string) $request->getBody();

        if (!strlen($body)) {
            return clone $request;
        }

        $hashedBody = $this->digest->hash((string) $body);

        /** @var RequestInterface $request */
        $request =  $request->withHeader('X-Authorization-Content-SHA256', $hashedBody);

        return $request;
    }

    /**
     * {@inheritDoc}
     */
    public function getAuthorizedRequest(RequestInterface $request, array $customHeaders = [])
    {
        if ($request->hasHeader('Authorization')) {
            $authHeader = AuthorizationHeader::createFromRequest($request);
        } else {
            $authHeader = $this->buildAuthorizationHeader($request, $customHeaders);
        }

        /** @var RequestInterface $request */
        $request = $request->withHeader('Authorization', (string) $authHeader);

        return $request;
    }

    /**
     * Builds an AuthorizationHeader object.
     *
     * @param \Psr\Http\Message\RequestInterface $request
     *   The request being signed.
     * @param string[] $customHeaders
     *   A list of custom header names. The values of the headers will be
     *   extracted from the request.
     *
     * @return \Acquia\Hmac\AuthorizationHeader
     *   The compiled authorizatio header object.
     */
    protected function buildAuthorizationHeader(RequestInterface $request, array $customHeaders = [])
    {
        $authHeaderBuilder = new AuthorizationHeaderBuilder($request, $this->key, $this->digest);
        $authHeaderBuilder->setRealm($this->realm);
        $authHeaderBuilder->setId($this->key->getId());
        $authHeaderBuilder->setCustomHeaders($customHeaders);

        return $authHeaderBuilder->getAuthorizationHeader();
    }
}
