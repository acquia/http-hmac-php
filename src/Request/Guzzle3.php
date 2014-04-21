<?php

namespace Acquia\Hmac\Request;

use Guzzle\Http\Message\Request;
use Guzzle\Http\Message\EntityEnclosingRequestInterface;

class Guzzle3 implements RequestInterface
{
    /**
     * @var \Guzzle\Http\Message\Request
     */
    protected $request;

    /**
     * @param \Guzzle\Http\Message\Request $request
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
        return $this->request->getHeader($header);
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
        return ($this->request instanceof EntityEnclosingRequestInterface) ? $this->request->getBody() : '';
    }

    /**
     * {@inheritDoc}
     */
    public function getResource()
    {
        return $this->request->getResource();
    }
}
