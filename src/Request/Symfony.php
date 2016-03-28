<?php

namespace Acquia\Hmac\Request;

use Symfony\Component\HttpFoundation\Request;

class Symfony implements RequestInterface
{
    /**
     * @var \Symfony\Component\HttpFoundation\Request
     */
    protected $request;

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
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
        return $this->request->headers->has($header);
    }

    /**
     * {@inheritDoc}
     */
    public function getHeader($header)
    {
        return $this->request->headers->get($header);
    }

    /**
     * {@inheritDoc}
     */
    public function getMethod()
    {
        return $this->request->getMethod();
    }

    // @TODO 3.0 Document
    public function getHost()
    {
        return $this->request->getUrl->getHost();
    }

    // @TODO 3.0 Document
    public function getPath()
    {
        return $this->request->getUrl->getPath();
    }

    // @TODO 3.0 Document
    // @TODO 3.0 Not sure of the format for this one.
    public function getQueryParameters() {
        return $this->request->getUrl->getQuery();
    }

    /**
     * {@inheritDoc}
     */
    public function getBody()
    {
        return (string) $this->request->getContent();
    }

    /**
     * {@inheritDoc}
     */
    public function getResource()
    {
        return $this->request->getRequestUri();
    }
}
