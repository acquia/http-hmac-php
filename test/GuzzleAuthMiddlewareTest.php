<?php

namespace Acquia\Hmac\Test;

use Acquia\Hmac\Guzzle\HmacAuthMiddleware;
use Acquia\Hmac\RequestSigner;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;

class GuzzleAuthMiddlewareTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @return \Acquia\Hmac\Guzzle\HmacAuthMiddleware
     */
    public function getMiddleware()
    {
        $signer = new RequestSigner();
        $signer->addCustomHeader('Custom1');

        return new HmacAuthMiddleware($signer, '1', 'secret-key');
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

    public function testSetDefaultDateHeader()
    {
        $middleware = $this->getMiddleware();

        $uri = 'http://example.com/resource/1?key=value';
        $request = $middleware->signRequest(new Request('GET', $uri, []));

        $date = $request->getHeaderLine('Date');
        $timestamp = strtotime($date);

        // It shouldn't take this test 10 seconds to run, but pad it since we
        // can not assume the time will be exactly the same.
        $difference = time() - $timestamp;
        $this->assertTrue($difference > -10);
        $this->assertTrue($difference < 10);
    }

    public function testAuthorizationHeader()
    {
        $middleware = $this->getMiddleware();

        $uri = 'http://example.com/resource/1?key=value';

        $headers = [
            'Content-Type' => 'text/plain',
            'Date' => 'Fri, 19 Mar 1982 00:00:04 GMT',
            'Custom1' => 'Value1',
        ];

        $request = $middleware->signRequest(new Request('GET', $uri, $headers, 'test content'));

        $expected = 'Acquia 1:' . DigestVersion1Test::EXPECTED_HASH;
        $this->assertEquals($expected, $request->getHeaderLine('Authorization'));
    }

    public function testRegisterPlugin()
    {
        $middleware = $this->getMiddleware();

        $container = [];
        $history = Middleware::history($container);

        $stack = new HandlerStack();
        $stack->setHandler(new MockHandler([new Response(200)]));
        $stack->push($middleware);
        $stack->push($history);

        $client = new Client([
            'base_url' => 'http://example.com',
            'handler' => $stack,
        ]);

        $client->get('/resource/1');

        $transaction = reset($container);
        $request = $transaction['request'];
        $authorization = $request->getHeaderLine('Authorization');

        $this->assertRegExp('@Acquia 1:([a-zA-Z0-9+/]+={0,2})$@', $authorization);
    }
}