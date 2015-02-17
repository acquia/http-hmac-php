<?php

namespace Acquia\Hmac\Request;

use GuzzleHttp\Message\Request;
use GuzzleHttp\Message\MessageInterface;

class Guzzle5 implements RequestInterface
{
    /**
     * @var \GuzzleHttp\Message\Request
     */
    protected $request;

    /**
     * @param \GuzzleHttp\Message\Request $request
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
        return (string) $this->request->getHeader($header);
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
        return ($this->request instanceof MessageInterface) ? $this->request->getBody() : '';
    }

    /**
     * {@inheritDoc}
     */
    public function getResource()
    {
        return $this->request->getResource();
    }
}
