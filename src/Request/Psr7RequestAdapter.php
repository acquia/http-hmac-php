<?php

namespace Acquia\Hmac\Request;

use Psr\Http\Message\RequestInterface as Psr7RequestInterface;

class Psr7RequestAdapter implements RequestInterface
{
    /**
     * @var Psr7RequestInterface
     */
    protected $request;

    /**
     * @param Psr7RequestInterface $request
     */
    public function __construct(Psr7RequestInterface $request)
    {
        $this->request = $request;
    }

    public function hasHeader($header)
    {
        return $this->request->hasHeader($header);
    }

    public function getHeader($header)
    {
        return (string) $this->request->getHeader($header)[0];
    }

    public function getMethod()
    {
        return $this->request->getMethod();
    }

    public function getBody()
    {
        return $this->request->getBody();
    }

    public function getResource()
    {
        return $this->request->getUri();
    }
}
