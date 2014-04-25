<?php

namespace Acquia\Hmac\Digest;

use Acquia\Hmac\RequestSignerInterface;
use Acquia\Hmac\Request\RequestInterface;

class Version1 extends DigestAbstract
{
    /**
     * {@inheritDoc}
     */
    protected function getMessage(RequestSignerInterface $requestSigner, RequestInterface $request)
    {
        $parts = array(
            $this->getMethod($request),
            $this->getHashedBody($request),
            $this->getContentType($requestSigner, $request),
            $this->getTimestamp($requestSigner, $request),
            $this->getCustomHeaders($requestSigner, $request),
            $this->getResource($request),
        );

        return join("\n", $parts);
    }

    /**
     * Returns the normalized HTTP mthod, e.g. GET, POST, etc.
     *
     * @param \Acquia\Hmac\Request\RequestInterface $request
     *
     * @return string
     */
    protected function getMethod(RequestInterface $request)
    {
        return strtoupper($request->getMethod());
    }

    /**
     * Returns the MD5 hash of the HTTP request body.
     *
     * @param \Acquia\Hmac\Request\RequestInterface $request
     *
     * @return string
     */
    protected function getHashedBody(RequestInterface $request)
    {
        return md5($request->getBody());
    }

    /**
     * Returns the normalized value of the "Content-type" header.
     *
     * @param \Acquia\Hmac\RequestSignerInterface $requestSigner
     * @param \Acquia\Hmac\Request\RequestInterface $request
     *
     * @return string
     */
    protected function getContentType(RequestSignerInterface $requestSigner, RequestInterface $request)
    {
        return strtolower($requestSigner->getContentType($request));
    }

    /**
     * Returns the value of the "Timestamp" header.
     *
     * @param \Acquia\Hmac\RequestSignerInterface $requestSigner
     * @param \Acquia\Hmac\Request\RequestInterface $request
     *
     * @return string
     */
    protected function getTimestamp(RequestSignerInterface $requestSigner, RequestInterface $request)
    {
        return $requestSigner->getTimestamp($request);
    }

    /**
     * Returns the canonicalized custom headers.
     *
     * @param \Acquia\Hmac\RequestSignerInterface $requestSigner
     * @param \Acquia\Hmac\Request\RequestInterface $request
     *
     * @return string
     */
    protected function getCustomHeaders(RequestSignerInterface $requestSigner, RequestInterface $request)
    {
        $headers = $requestSigner->getCustomHeaders($request);

        $canonicalizedHeaders = array();
        foreach ($headers as $header => $value) {
            $canonicalizedHeaders[] = strtolower($header) . ': ' . $value;
        }

        sort($canonicalizedHeaders);
        return join("\n", $canonicalizedHeaders);
    }

    /**
     * Returns the canonicalized resource, which is a normalized path plus query
     * string.
     *
     * @param \Acquia\Hmac\Request\RequestInterface $request
     *
     * @return string
     */
    protected function getResource(RequestInterface $request)
    {
        return $request->getResource();
    }
}
