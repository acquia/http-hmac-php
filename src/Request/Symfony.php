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
    public function getMethod()
    {
        return $this->request->getMethod();
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
    public function getTimestamp($header)
    {
        return $this->request->headers->get($header);
    }

    /**
     * {@inheritDoc}
     */
    public function getResource()
    {
        $queryString = $this->request->getQueryString();
        if (null !== $queryString) {
            $queryString = '?' . $queryString;
        }

        return $this->request->getBasePath() . $this->request->getBasePath() . $queryString;
    }
}
