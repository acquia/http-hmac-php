<?php

namespace Acquia\Hmac\Request;

use GuzzleHttp\Psr7\Request;

class Guzzle implements RequestInterface
{
    /**
     * @var \GuzzleHttp\Psr7\Request
     */
    protected $request;

    /**
     * @param \GuzzleHttp\Psr7\Request $request
     */
    public function __construct(Request $request)
    {
        $this->request = $request;
    }

    /**
     * {@inheritDoc}
     */
    public function hasHeader($header)
    {
        return $this->request->hasHeader($header);
    }

    /**
     * {@inheritDoc}
     */
    public function getHeader($header)
    {
        return $this->request->getHeaderLine($header);
    }

    /**
     * {@inheritDoc}
     */
    public function getMethod()
    {
        return $this->request->getMethod();
    }

    /**
     * {@inheritDoc}
     */
    public function getBody()
    {

        return $this->request->getBody();
    }

    /**
     * {@inheritDoc}
     */
    public function getResource()
    {
        return $this->request->getRequestTarget();
    }
}
