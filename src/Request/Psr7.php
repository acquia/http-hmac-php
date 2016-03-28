<?php

namespace Acquia\Hmac\Request;

use Psr\Http\Message\RequestInterface as Psr7RequestInterface;

class Psr7 implements RequestInterface
{
    /**
     * @var \Psr\Http\Message\RequestInterface
     */
    protected $request;

    /**
     * @param \Psr\Http\Message\RequestInterface $request
     */
    public function __construct(Psr7RequestInterface $request)
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
        return (string) $this->request->getBody();
    }

    // @TODO 3.0 Document
    public function getHost()
    {
        return $this->request->getUri->getHost();
    }

    // @TODO 3.0 Document
    public function getPath()
    {
        return $this->request->getUri->getPath();
    }

    // @TODO 3.0 Document
    // @TODO 3.0 Not sure of the format for this one.
    public function getQueryParameters() {
        return $this->request->getUri->getQuery();
    }

    /**
     * {@inheritDoc}
     */
    public function getResource()
    {
        return $this->request->getRequestTarget();
    }
}
