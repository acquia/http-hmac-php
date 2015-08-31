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
     * {@inheritdoc}
     */
    public function hasHeader($header)
    {
        return $this->request->hasHeader($header);
    }

    /**
     * {@inheritdoc}
     */
    public function getHeader($header)
    {
        $headers = $this->request->getHeader($header);

        return reset($headers);
    }

    /**
     * {@inheritdoc}
     */
    public function getMethod()
    {
        return $this->request->getMethod();
    }

    /**
     * {@inheritdoc}
     */
    public function getBody()
    {
        return (string) $this->request->getBody();
    }

    /**
     * {@inheritdoc}
     */
    public function getResource()
    {
        $url = $this->request->getUri();
        $resource = $url->getPath();
        $query = $url->getQuery();
        $fragment = $url->getFragment();
        if (!empty($query)) {
            $resource .= '?'.$query;
        }
        if (!empty($fragment)) {
            $resource .= '#'.$fragment;
        }

        return $resource;
    }
}
