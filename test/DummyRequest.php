<?php

namespace Acquia\Hmac\Test;

use Acquia\Hmac\Request\RequestInterface;

class DummyRequest implements RequestInterface
{
    public $body = 'test content';
    public $headers = array();
    public $method = 'GET';
    public $resource = '/resource/1?key=value';

    public function getBody()
    {
        return $this->body;
    }

    public function getHeader($header)
    {
        return (isset($this->headers[$header])) ? $this->headers[$header] : NULL;
    }

    public function getMethod()
    {
        return $this->method;
    }

    public function getResource()
    {
        return $this->resource;
    }

    public function hasHeader($header)
    {
        return isset($this->headers[$header]);
    }
}
