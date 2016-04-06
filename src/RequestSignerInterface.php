<?php

namespace Acquia\Hmac;

//use Acquia\Hmac\Request\RequestInterface;
use GuzzleHttp\Psr7\Request;

interface RequestSignerInterface
{
    /**
     * Generates a signature for the request given the secret key and algorithm.
     *
     * @param \Acquia\Hmac\Request\RequestInterface $request
     * @param string $secretKey
     *
     * @return string
     */
    public function signRequest(Request $request, $secretKey);

    /**
     * Returns the value of the "Authorization" header.
     *
     * @param \Acquia\Hmac\Request\RequestInterface $request
     * @param string $id
     * @param string $secretKey
     * @param string $nonce
     *
     * @return string
     */
    public function getAuthorization(Request $request, $id, $secretKey, $nonce = null);

    /**
     * Gets the signature passed through the HTTP request.
     *
     * @param \Acquia\Hmac\Request\RequestInterface $request
     *
     * @return \Acquia\Hmac\SignatureInterface
     */
    public function getSignature(Request $request);

    /**
     * Returns the content type passed through the request.
     *
     * @param \Acquia\Hmac\Request\RequestInterface $request
     *
     * @return string
     *
     * @throws \Acquia\Hmac\Exception\MalformedRequestException
     */
    public function getContentType(Request $request);

    /**
     * Returns timestamp passed through the request.
     *
     * @param \Acquia\Hmac\Request\RequestInterface $request
     *
     * @return string
     *
     * @throws \Acquia\Hmac\Exception\MalformedRequestException
     */
    public function getTimestamp(Request $request);

    /**
     * Returns an associative array of custom headers.
     *
     * @param \Acquia\Hmac\Request\RequestInterface $request
     *
     * @return string
     *
     * @throws \Acquia\Hmac\Exception\MalformedRequestException
     */
    public function getCustomHeaders(Request $request);
}
