<?php

namespace Acquia\Hmac;

use Psr\Http\Message\RequestInterface;

class RequestSigner implements RequestSignerInterface
{
    /**
     * @var \Acquia\Hmac\Digest\DigestInterface
     */
    protected $digest;

    /**
     * @var string
     */
    protected $id;

    /**
     * @var int
     */
    protected $timestamp;

    /**
     * @var array
     */
    protected $customHeaders = array();

    /**
     * @var string
     */
    protected $defaultContentType = 'application/json; charset=utf-8';

    // @TODO 3.0 documentation/interface
    // @TODO 3.0 setter?
    protected $authorizationHeader;

    /**
     * @param \Acquia\Hmac\Digest\DigestInterface $digest
     */
    public function __construct(Digest\DigestInterface $digest = null, AuthorizationHeaderInterface $authorization_header = null)
    {
        $this->digest = $digest ?: new Digest\Version2();
        $this->authorizationHeader = $authorization_header ?: new AuthorizationHeader();
    }

    // @TODO 3.0 Interface/doc/test
    public function getAuthorizationHeader()
    {
      return $this->authorizationHeader;
    }

    // @TODO 3.0 Interface/doc/test
    public function getId()
    {
        return $this->id;
    }

    // @TODO 3.0 Interface/doc/test
    public function setId($id)
    {
        $this->id = $id;
    }

    /**
     * @var string $contentType
     */
    // @TODO 3.0 Interface/test
    public function setDefaultContentType($contentType)
    {
        $this->defaultContentType = $contentType;
    }

    /**
     * @return string
     */
    // @TODO 3.0 Interface/test
    public function getDefaultContentType()
    {
        return $this->defaultContentType;
    }

    // @TODO 3.0 getters/setters at top.

    // @TODO 3.0 Interface/test
    public function signRequest(RequestInterface $request, $secretKey)
    {
        // @TODO 3.0 do we still need getters/setters for $id?
        if (!$request->hasHeader('X-Authorization-Timestamp')) {
            $request = $request->withHeader('X-Authorization-Timestamp', $this->getTimestamp());
        }

        if (!$request->hasHeader('Content-Type')) {
            $request = $request->withHeader('Content-Type', $this->getDefaultContentType());
        }

        if (!$request->hasHeader('X-Authorization-Content-SHA256')) {
            $hashed_body = $this->getHashedBody($request);
            if (!empty($hashed_body)) {
                $request = $request->withHeader('X-Authorization-Content-SHA256', $hashed_body);
            }
        }

        $authorization = $this->getAuthorization(
            $request,
            $this->getAuthorizationHeader()->getId(),
            $secretKey
        );
        $signed_request = $request->withHeader('Authorization', $authorization);
        return $signed_request;
    }

    /**
     * {@inheritDoc}
     *
     * @throws \Acquia\Hmac\Exception\MalformedRequest
     */
    public function getSignature(RequestInterface $request)
    {
        // @TODO 3.0 better AuthHeader handling, probably new class
        $header = $request->getHeaderLine('Authorization');
        if (!$request->hasHeader('Authorization')) {
            throw new Exception\MalformedRequestException('Authorization header required');
        }

        $id = '';
        $id_match = preg_match('/.*id="(.*?)"/', $header, $id_matches);

        $signature = '';
        $signature_match = preg_match('/.*signature="(.*?)"/', $header, $signature_matches);

        if (!$id_match) {
            throw new Exception\KeyNotFoundException('Authorization header requires an id.');
        }

        if (!$signature_match) {
            throw new Exception\KeyNotFoundException('Authorization header requires a signature.');
        }

        $id = $id_matches[1];
        $signature = $signature_matches[1];

        // Ensure the signature is a base64 encoded string.
        if (!preg_match('@^[a-zA-Z0-9+/]+={0,2}$@', $signature)) {
            throw new Exception\MalformedRequestException('Invalid signature in authorization header');
        }

        $timestamp = $this->getTimestamp();
        if (!$timestamp || !is_numeric($timestamp) || (int) $timestamp < 0) {
            throw new Exception\MalformedRequestException('Timestamp not valid');
        }

        return new Signature(stripslashes($id), $signature, $timestamp);
    }

    /**
     * {@inheritDoc}
     *
     * @throws \InvalidArgumentException
     * @throws \Acquia\Hmac\Exception\InvalidRequestException
     */
    public function getDigest(RequestInterface $request, $secretKey)
    {
        return $this->digest->get($this, $request, $secretKey);
    }

    // @TODO 3.0 Interface
    // @TODO 3.0 Test
    public function getHashedBody(RequestInterface $request)
    {
        $hash = '';
        if (!empty((string) $request->getBody())) {
            $hash = $this->digest->getHashedBody($request);
        }
        return $hash;
    }

    /**
     * {@inheritDoc}
     *
     * @throws \Acquia\Hmac\Exception\InvalidRequestException
     */
    public function getAuthorization(RequestInterface $request, $id, $secretKey)
    {
        // @TODO 3.0 creating the signature probably belongs elsewhere.
        $this->authorizationHeader->setSignature($this->getDigest($request, $secretKey));
        return $this->authorizationHeader->createAuthorizationHeader();
    }

    /**
     * {@inheritDoc}
     */
    public function getContentType(RequestInterface $request)
    {
        return $request->getHeaderLine('Content-Type');
    }

    /**
     * {@inheritDoc}
     */
    public function getTimestamp()
    {
        if (empty($this->timestamp)) {
            $time = new \DateTime();
            $time->setTimezone(new \DateTimeZone('GMT'));
            $this->timestamp = $time->getTimestamp();
        }

        return $this->timestamp;
    }

    /**
     * {@inheritDoc}
     */
    public function setTimestamp($timestamp)
    {
        $this->timestamp = (int) $timestamp;
    }
}
