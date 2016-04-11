<?php

namespace Acquia\Hmac;

use Psr\Http\Message\RequestInterface;

interface RequestSignerInterface
{
    /**
     * Sign a request with the appropriate headers.
     *
     * This will clone the request according to the PSR-7 standard with all of
     * the headers required by the Acquia HTTP HMAC spec.
     *
     * @param \Psr\Http\Message\RequestInterface $request
     *   The request to sign.
     * @param string[] $customHeaders
     *   A list of custom header names. The values of the headers will be
     *   extracted from the request.
     *
     * @return \Psr\Http\Message\RequestInterface $request
     *   The signed request.
     */
    public function signRequest(RequestInterface $request, array $customHeaders = []);

    /**
     * Adds the timestamp to the request.
     *
     * @param \Psr\Http\Message\RequestInterface $request
     *   The request being signed.
     * @param \DateTime
     *   The date to timestamp the request with. Defaults to now.
     *
     * @return \Psr\Http\Message\RequestInterface $request
     *   A cloned request with the X-Authorization-Timestamp header filled out.
     */
    public function getTimestampedRequest(RequestInterface $request, \DateTime $date);

    /**
     * Adds a hashed a hash for the request body.
     *
     * @param \Acquia\Hmac\KeyInterface $key
     *   The request for which to generate the hashed Body.
     *
     * @return \Psr\Http\Message\RequestInterface $request
     *   A cloned request. If the request has a body, the
     *   X-Authorization-Content-SHA256 header will be filled out.
     */
    public function getContentHashedRequest(RequestInterface $request);

    /**
     * Adds the constructed Authorization header to the request.
     *
     * @param \Psr\Http\Message\RequestInterface $request
     *   The request being signed.
     * @param string[] $customHeaders
     *   A list of custom header names. The values of the headers will be
     *   extracted from the request.
     *
     * @return \Psr\Http\Message\RequestInterface $request
     *   A cloned request with the Authorization header filled out.
     */
    public function getAuthorizedRequest(RequestInterface $request, array $customHeaders = []);
}
