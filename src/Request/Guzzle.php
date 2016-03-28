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

    // @TODO 3.0 Implement
    public function getHost() {
      $port = $this->request->getUri()->getPort();
      $host = $this->request->getUri()->getHost();
      $host_string = empty($port) ? $host : "$host:$port";
      return $host_string;
    }

    // @TODO 3.0 Implement
    public function getPath() {
      return $this->request->getUri()->getPath();
    }

    // @TODO 3.0 Implement
    public function getQueryParameters() {
      return $this->request->getUri()->getQuery();
    }

    /**
     * {@inheritDoc}
     */
    public function getBody()
    {
        return $this->request->getBody();
    }
}
