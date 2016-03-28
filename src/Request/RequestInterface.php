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

    // @TODO 3.0 Document
    public function getHost();

    // @TODO 3.0 Document
    public function getPath();

    // @TODO 3.0 Document
    public function getQueryParameters();

    /**
     * Returns the raw request body.
     *
     * @return string
     */
    public function getBody();
}
