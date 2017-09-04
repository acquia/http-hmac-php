<?php

namespace Acquia\Hmac;

use Acquia\Hmac\Digest\DigestInterface;
use Acquia\Hmac\Digest\Digest;
use Acquia\Hmac\Exception\MalformedRequestException;
use Psr\Http\Message\RequestInterface;

/**
 * Constructs AuthorizationHeader objects.
 */
class AuthorizationHeaderBuilder
{
    /**
     * @var \Psr\Http\Message\RequestInterface
     *   The request for which to generate the authorization header.
     */
    protected $request;

    /**
     * @var \Acquia\Hmac\KeyInterface
     *   The key with which to sign the authorization header.
     */
    protected $key;

    /**
     * @var \Acquia\Hmac\Digest\DigestInterface
     *  The message digest used to generate the header signature.
     */
    protected $digest;

    /**
     * @var string
     *   The realm/provider.
     */
    protected $realm = 'Acquia';

    /**
     * @var string
     *   The API key's unique identifier.
     */
    protected $id;

    /**
     * @var string
     *   The nonce.
     */
    protected $nonce;

    /**
     * @var string
     *   The spec version.
     */
    protected $version = '2.0';

    /**
     * @var string[]
     *   The list of custom headers.
     */
    protected $headers = [];

    /**
     * @var string
     *   The authorization signature.
     */
    protected $signature;

    /**
     * Initializes the builder with a message digest.
     *
     * @param \Psr\Http\Message\RequestInterface $request
     *   The request for which to generate the authorization header.
     * @param \Acquia\Hmac\KeyInterface $key
     *   The key with which to sign the authorization header.
     * @param \Acquia\Hmac\Digest\DigestInterface $digest
     *   The message digest to use when signing requests. Defaults to
     *   \Acquia\Hmac\Digest\Digest.
     */
    public function __construct(RequestInterface $request, KeyInterface $key, DigestInterface $digest = null)
    {
        $this->request = $request;
        $this->key     = $key;
        $this->digest  = $digest ?: new Digest();
        $this->nonce   = $this->generateNonce();
    }

    /**
     * Set the realm/provider.
     *
     * This method is optional: if not called, the realm will be "Acquia".
     *
     * @param string $realm
     *   The realm/provider.
     */
    public function setRealm($realm)
    {
        $this->realm = $realm;
    }

    /**
     * Set the API key's unique identifier.
     *
     * This method is required for an authorization header to be built.
     *
     * @param string $id
     *   The API key's unique identifier.
     */
    public function setId($id)
    {
        $this->id = $id;
    }

    /**
     * Set the nonce.
     *
     * This is optional: if not called, a nonce will be generated automatically.
     *
     * @param string $nonce
     *   The nonce. The nonce should be hex-based v4 UUID.
     */
    public function setNonce($nonce)
    {
        $this->nonce = $nonce;
    }

    /**
     * Set the spec version.
     *
     * This is optional: if not called, the version will be "2.0".
    *
     * @param string $version
     *   The spec version.
     */
    public function setVersion($version)
    {
        $this->version = $version;
    }

    /**
     * Set the list of custom headers found in a request.
     *
     * This is optional: if not called, the list of custom headers will be
     * empty.
     *
     * @param string[] $headers
     *   A list of custom header names. The values of the headers will be
     *   extracted from the request.
     */
    public function setCustomHeaders(array $headers = [])
    {
        $this->headers = $headers;
    }

    /**
     * Set the authorization signature.
     *
     * This is optional: if not called, the signature will be generated from the
     * other fields and the request. Calling this method manually is not
     * recommended outside of testing.
     *
     * @param string $signature
     *   The Base64-encoded authorization signature.
     */
    public function setSignature($signature)
    {
        $this->signature = $signature;
    }

    /**
     * Builds the authorization header.
     *
     * @throws \Acquia\Hmac\Exception\MalformedRequestException
     *   When a required field (ID, nonce, realm, version) is empty or missing.
     *
     * @return \Acquia\Hmac\AuthorizationHeader
     *   The compiled authorization header.
     */
    public function getAuthorizationHeader()
    {
        if (empty($this->realm) || empty($this->id) || empty($this->nonce) || empty($this->version)) {
            throw new MalformedRequestException(
                'One or more required authorization header fields (ID, nonce, realm, version) are missing.',
                null,
                0,
                $this->request
            );
        }

        $signature = !empty($this->signature) ? $this->signature : $this->generateSignature();

        return new AuthorizationHeader(
            $this->realm,
            $this->id,
            $this->nonce,
            $this->version,
            $this->headers,
            $signature
        );
    }

    /**
     * Generate a new nonce.
     *
     * The nonce is a v4 UUID.
     *
     * @return string
     *   The generated nonce.
     */
    public function generateNonce()
    {
        return sprintf(
            '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            // 32 bits for "time_low"
            mt_rand(0, 0xffff),
            mt_rand(0, 0xffff),
            // 16 bits for "time_mid"
            mt_rand(0, 0xffff),
            // 16 bits for "time_hi_and_version",
            // four most significant bits holds version number 4
            mt_rand(0, 0x0fff) | 0x4000,
            // 16 bits, 8 bits for "clk_seq_hi_res",
            // 8 bits for "clk_seq_low",
            // two most significant bits holds zero and one for variant DCE1.1
            mt_rand(0, 0x3fff) | 0x8000,
            // 48 bits for "node"
            mt_rand(0, 0xffff),
            mt_rand(0, 0xffff),
            mt_rand(0, 0xffff)
        );
    }

    /**
     * Generate a signature from the request.
     *
     * @throws \Acquia\Hmac\Exception\MalformedRequestException
     *   When a required header is missing.
     *
     * @return string
     *   The generated signature.
     */
    protected function generateSignature()
    {
        if (!$this->request->hasHeader('X-Authorization-Timestamp')) {
            throw new MalformedRequestException(
                'X-Authorization-Timestamp header missing from request.',
                null,
                0,
                $this->request
            );
        }

        $host = $this->request->getUri()->getHost();
        $port = $this->request->getUri()->getPort();

        if ($port) {
            $host .= ':' . $port;
        }

        $parts = [
            strtoupper($this->request->getMethod()),
            $host,
            $this->request->getUri()->getPath(),
            $this->request->getUri()->getQuery(),
            $this->serializeAuthorizationParameters(),
        ];

        $parts = array_merge($parts, $this->normalizeCustomHeaders());

        $parts[] = $this->request->getHeaderLine('X-Authorization-Timestamp');

        $body = (string) $this->request->getBody();

        if (strlen($body)) {
            if ($this->request->hasHeader('Content-Type')) {
                $parts[] = $this->request->getHeaderLine('Content-Type');
            }

            $parts[] = $this->digest->hash((string) $body);
        }

        return $this->digest->sign(implode("\n", $parts), $this->key->getSecret());
    }

    /**
     * Serializes the requireed authorization parameters.
     *
     * @return string
     *   The serialized authorization parameter string.
     */
    protected function serializeAuthorizationParameters()
    {
        return sprintf(
            'id=%s&nonce=%s&realm=%s&version=%s',
            $this->id,
            $this->nonce,
            rawurlencode($this->realm),
            $this->version
        );
    }

    /**
     * Normalizes the custom headers for signing.
     *
     * @return string[]
     *   An array of normalized headers.
     */
    protected function normalizeCustomHeaders()
    {
        $headers = [];

        // The spec requires that headers are sorted by header name.
        sort($this->headers);
        foreach ($this->headers as $header) {
            if ($this->request->hasHeader($header)) {
                $headers[] = strtolower($header) . ':' . $this->request->getHeaderLine($header);
            }
        }

        return $headers;
    }
}
