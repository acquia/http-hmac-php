<?php

namespace Acquia\Hmac\Test;

use Acquia\Hmac\Guzzle\HmacAuthMiddleware;
use Acquia\Hmac\RequestSigner;
use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Subscriber\Mock;
use GuzzleHttp\Stream\Stream;

class GuzzleAuthMiddlewareTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @return \Acquia\Hmac\Guzzle\HmacAuthMiddleware
     */
    public function getMiddleware()
    {
        $signer = new RequestSigner();
        $signer->addCustomHeader('Custom1');

        $middleware = new HmacAuthMiddleware($signer, '1', 'secret-key');
        return $middleware;
    }

    public function testGetDefaultContentType()
    {
        $middleware = $this->getMiddleware();
        $this->assertEquals('application/json; charset=utf-8', $middleware->getDefaultContentType());
    }

    public function testSetDefaultContentType()
    {
        $middleware = $this->getMiddleware();
        $middleware->setDefaultContentType('text/plain');
        $this->assertEquals('text/plain', $middleware->getDefaultContentType());
    }

    public function testSetDefaultContentTypeHeader()
    {
        $middleware = $this->getMiddleware();
        $middleware->setDefaultContentType('some/content-type');

        $uri = 'http://example.com/resource/1?key=value';
        $request = $middleware->signRequest(new Request('GET', $uri, []));
        $this->assertEquals('some/content-type', $request->getHeaderLine('Content-Type'));
    }
}