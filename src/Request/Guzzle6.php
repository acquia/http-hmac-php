<?php

namespace Acquia\Hmac\Request;

use GuzzleHttp\Psr7\Request;

class Guzzle6 implements RequestInterface
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
        $headers = $this->request->getHeader($header);
        return reset($headers);
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

    /**
     * {@inheritDoc}
     */
    public function getResource()
    {
        $url = $this->request->getUri();
        $resource = $url->getPath();
        $query = $url->getQuery();
        $fragment = $url->getFragment();
        if (!empty($query)) {
          $resource .= '?' . $query;
        }
        if (!empty($fragment)) {
          $resource .= '#' . $fragment;
        }
      return $resource;
    }
}
