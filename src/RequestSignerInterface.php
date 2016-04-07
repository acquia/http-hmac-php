<?php

namespace Acquia\Hmac;

use Psr\Http\Message\RequestInterface;

interface RequestSignerInterface
{
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

    /**
     * Returns an associative array of custom headers.
     *
     * @param \Psr\Http\Message\RequestInterface $request
     *
     * @return string
     *
     * @throws \Acquia\Hmac\Exception\MalformedRequestException
     */
    public function getCustomHeaders(RequestInterface $request);
}
