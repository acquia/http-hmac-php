<?php

namespace Acquia\Hmac;

use Psr\Http\Message\RequestInterface;

interface RequestSignerInterface
{

    /**
     * Gets the AuthorizationHeader object.
     *
     * @return \Acquia\Hmac\AuthorizationHeader
     */
    public function getAuthorizationHeader();

    /**
     * Adds a signed header to the AuthorizationHeader.
     *
     * @param string $key
     */
    public function addSignedHeader($key);

    /**
     * Gets all signed headers from the AuthorizationHeader.
     *
     * @return Array
     */
    public function getSignedHeaders();

    /**
     * Gets the realm from the AuthorizationHeader.
     *
     * @return string
     */
    public function getHeaderRealm();

    /**
     * Sets the realm in the AuthorizationHeader.
     *
     * @param string $realm
     */
    public function setHeaderRealm($realm);

    /**
     * Gets the ID from the AuthorizationHeader.
     *
     * @return string
     */
    public function getHeaderId();

    /**
     * Sets the ID in the AuthorizationHeader.
     *
     * @param string $id
     */
    public function setHeaderId($id);

    /**
     * Gets the nonce from the AuthorizationHeader.
     *
     * @return string
     */
    public function getHeaderNonce();

    /**
     * Sets the nonce in the AuthorizationHeader.
     *
     * @param string $nonce
     */
    public function setHeaderNonce($nonce);

    /**
     * Gets the version from the AuthorizationHeader.
     *
     * @return string
     */
    public function getHeaderVersion();

    /**
     * Sets the version in the AuthorizationHeader.
     *
     * @param string
     */
    public function setHeaderVersion($version);

    /**
     * Gets the signature from the AuthorizationHeader.
     *
     * @return string
     */
    public function getHeaderSignature();

    /**
     * Sets the signature in the AuthorizationHeader.
     *
     * @param string $signature
     */
    public function setHeaderSignature($signature);

    /**
     * Generates a signature for the request given the secret key and algorithm.
     *
     * @param \Psr\Http\Message\RequestInterface $request
     * @param string $secretKey
     *
     * @return string
     */
    public function getDigest(RequestInterface $request, $secretKey);

    /**
     * Sets the default content type.
     *
     * @param string $content_type
     */
    public function setDefaultContentType($content_type);

    /**
     * Gets the default content type.
     *
     * @return string
     */
    public function getDefaultContentType();

    /**
     * Sign a request with the appropriate headers.
     *
     * This will clone the request according to the PSR7 standard with all of
     * the headers required by the Acquia HMAC spec.
     *
     * @param \Psr\Http\Message\RequestInterface $request
     * @param string $secretKey
     *
     * @param \Psr\Http\Message\RequestInterface $request
     */
    public function signRequest(RequestInterface $request, $secretKey);

    /**
     * Returns the value of the "Authorization" header.
     *
     * @param \Psr\Http\Message\RequestInterface $request
     * @param string $id
     * @param string $secretKey
     *
     * @return string
     */
    public function getAuthorization(RequestInterface $request, $id, $secretKey);

    /**
     * Gets the signature passed through the HTTP request.
     *
     * @param \Psr\Http\Message\RequestInterface $request
     *
     * @return \Acquia\Hmac\SignatureInterface
     */
    public function getSignature(RequestInterface $request);

    /**
     * Returns the content type passed through the request.
     *
     * @param \Psr\Http\Message\RequestInterface $request
     *
     * @return string
     *
     * @throws \Acquia\Hmac\Exception\MalformedRequestException
     */
    public function getContentType(RequestInterface $request);

    /**
     * Returns timestamp passed through the request.
     *
     * @return int
     *
     * @throws \Acquia\Hmac\Exception\MalformedRequestException
     */
    public function getTimestamp();

    /**
     * Returns the correctly hashed request body.
     *
     * @param \Psr\Http\Message\RequestInterface $request
     *
     * @return string
     */
    public function getHashedBody(RequestInterface $request);

    /**
     * Returns timestamp passed through the request.
     *
     * @param int $timestamp
     */
    public function setTimestamp($timestamp);
}
