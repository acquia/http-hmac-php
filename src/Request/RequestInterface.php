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
     * @param string $header
     *
     * @return string
     */
    public function getHeader($header);

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
     * Returns the resource, which is the path + query string + fragment of the request.
     *
     * @return string
     */
    public function getResource();
}
