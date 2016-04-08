<?php

namespace Acquia\Hmac\Test;

use GuzzleHttp\Psr7\Request;

class DummyRequest extends Request
{
    public static function generate(
        $method = 'GET',
        $host = 'https://example.acquiapipet.net',
        $path = '/v1.0/task-status/133',
        $query = 'limit=10',
        $headers = [],
        $body = null
    ) {
        $query_string = is_null($query) ? '' : '?' . $query;
        return new static($method, $host . $path . $query_string, $headers, $body);
    }
}
