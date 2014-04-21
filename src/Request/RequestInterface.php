<?php

namespace Acquia\Hmac\Request;

interface RequestInterface
{
    /**
     * @param string $header
     *
     * @return bool
     */
    public function hasHeader($header);

    /**
     * Returns the HTTP method.
     *
     * @return string
     */
    public function getMethod();

    /**
     * Returns the raw request body.
     *
     * @return string
     */
    public function getBody();

    /**
     * @param array $headers
     *
     * @return string
     */
    public function getTimestamp(array $headers);

    /**
     * Returns the resource, which is the path + query string of the request.
     *
     * @return string
     */
    public function getResource();
}
