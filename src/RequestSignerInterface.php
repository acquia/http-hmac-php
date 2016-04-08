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
     * Returns timestamp passed through the request.
     *
     * @param int $timestamp
     */
    public function setTimestamp($timestamp);
}
