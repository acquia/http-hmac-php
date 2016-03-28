<?php

namespace Acquia\Hmac\Test;

use Acquia\Hmac\Request\RequestInterface;

class DummyRequest implements RequestInterface
{
    public $body = '';
    public $headers = array();
    public $method = 'GET';
    public $host = 'example.acquiapipet.net';
    public $path = '/v1.0/task-status/133';
    public $queryParameters = 'limit=10';

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

    public function getHost()
    {
        return $this->host;
    }

    public function getPath()
    {
        return $this->path;
    }

    public function getQueryParameters() {
        return $this->queryParameters;
    }

    public function hasHeader($header)
    {
        return isset($this->headers[$header]);
    }
}
