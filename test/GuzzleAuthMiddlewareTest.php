<?php

namespace Acquia\Hmac\Test;

use Acquia\Hmac\Guzzle\HmacAuthMiddleware;
use Acquia\Hmac\Request\Psr7;
use Acquia\Hmac\RequestSigner;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;

class GuzzleAuthMiddlewareTest extends \PHPUnit_Framework_TestCase
{
    protected $auth_id;

    protected $auth_secret;

    protected function setUp()
    {
        $this->auth_id = 'efdde334-fe7b-11e4-a322-1697f925ec7b';
        $this->auth_secret = 'W5PeGMxSItNerkNFqQMfYiJvH14WzVJMy54CPoTAYoI=';
    }

    /**
     * @return \Acquia\Hmac\Guzzle\HmacAuthMiddleware
     */
    public function getMiddleware(RequestSigner $requestSigner = null, $id = null, $secret = null)
    {
        if (empty($requestSigner)) {
            $requestSigner = new RequestSigner();
        }

        if (empty($id)) {
            $id = $this->auth_id;
        } 
        if (empty($secret)) {
            $secret = $this->auth_secret;
        }
       
        return new HmacAuthMiddleware($requestSigner, $id, $secret);
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

        $timestamp = (int) $request->getHeaderLine('X-Authorization-Timestamp');

        // It shouldn't take this test 10 seconds to run, but pad it since we
        // can not assume the time will be exactly the same.
        $difference = time() - $timestamp;
        $this->assertTrue($difference > -10);
        $this->assertTrue($difference < 10);
    }

    public function testAuthorizationHeader()
    {
        $requestSigner = new RequestSigner();
        $requestSigner->setId('efdde334-fe7b-11e4-a322-1697f925ec7b');
        $requestSigner->setRealm('Pipet service');
        $requestSigner->setNonce('d1954337-5319-4821-8427-115542e08d10');

        $middleware = $this->getMiddleware($requestSigner, $requestSigner->getId(), $this->auth_secret);

        $uri = 'https://example.acquiapipet.net/v1.0/task-status/133?limit=10';

        $headers = [
          'X-Authorization-Timestamp' => '1432075982',
        ];
        $request = $middleware->signRequest(new Request('GET', $uri, $headers));

        $expected = 'acquia-http-hmac realm="Pipet service",'
                    . 'id="efdde334-fe7b-11e4-a322-1697f925ec7b",'
                    . 'nonce="d1954337-5319-4821-8427-115542e08d10",'
                    . 'version="2.0",'
                    . 'headers="",'
                    . 'signature="MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc="';
        $this->assertEquals($expected, $request->getHeaderLine('Authorization'));
    }

    public function testRegisterPlugin()
    {
        $requestSigner = new RequestSigner();
        $requestSigner->setId('efdde334-fe7b-11e4-a322-1697f925ec7b');
        $requestSigner->setRealm('Pipet service');
        $requestSigner->setNonce('d1954337-5319-4821-8427-115542e08d10');

        $middleware = $this->getMiddleware($requestSigner, $requestSigner->getId(), $this->auth_secret);

        $container = [];
        $history = Middleware::history($container);

        $stack = new HandlerStack();
        $stack->setHandler(new MockHandler([new Response(200)]));
        $stack->push($middleware);
        $stack->push($history);

        $client = new Client([
            'base_uri' => 'https://example.acquiapipet.net/',
            'handler' => $stack,
        ]);

        $headers = [
            'X-Authorization-Timestamp' => '1432075982',
        ];

        $client->request('GET', '/v1.0/task-status/133', [
          'query' => ['limit' => '10'],
          'headers' => $headers,
        ]);

        $transaction = reset($container);
        $request = $transaction['request'];

        $expected = 'acquia-http-hmac realm="Pipet service",'
                    . 'id="efdde334-fe7b-11e4-a322-1697f925ec7b",'
                    . 'nonce="d1954337-5319-4821-8427-115542e08d10",'
                    . 'version="2.0",'
                    . 'headers="",'
                    . 'signature="MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc="';
        $this->assertEquals($expected, $request->getHeaderLine('Authorization'));

    }
}
