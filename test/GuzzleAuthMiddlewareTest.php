<?php

namespace Acquia\Hmac\Test;

use Acquia\Hmac\AuthorizationHeaderBuilder;
use Acquia\Hmac\Guzzle\HmacAuthMiddleware;
use Acquia\Hmac\Key;
use Acquia\Hmac\Test\Mocks\MockHmacAuthMiddleware;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;

/**
 * Tests the HTTP HMAC Guzzle middleware.
 */
class GuzzleAuthMiddlewareTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var \Acquia\Hmac\KeyInterface
     *   A sample key.
     */
    protected $authKey;

    protected function setUp()
    {
        $authId = 'efdde334-fe7b-11e4-a322-1697f925ec7b';
        $authSecret = 'W5PeGMxSItNerkNFqQMfYiJvH14WzVJMy54CPoTAYoI=';

        $this->authKey = new Key($authId, $authSecret);
    }

    /**
     * Ensures the HTTP HMAC middleware timestamps requests correctly.
     */
    public function testSetDefaultDateHeader()
    {
        $middleware = new HmacAuthMiddleware($this->authKey);

        $uri = 'http://example.com/resource/1?key=value';
        $request = $middleware->signRequest(new Request('GET', $uri, []));

        $timestamp = (int) $request->getHeaderLine('X-Authorization-Timestamp');

        // It shouldn't take this test 10 seconds to run, but pad it since we
        // can not assume the time will be exactly the same.
        $difference = time() - $timestamp;
        $this->assertTrue($difference > -10);
        $this->assertTrue($difference < 10);
    }

    /**
     * Ensures the HTTP HMAC middleware signs requests correctly.
     */
    public function testAuthorizationHeader()
    {
        $realm = 'Pipet service';

        $headers = [
            'X-Authorization-Timestamp' => '1432075982',
        ];

        $request = new Request('GET', 'https://example.acquiapipet.net/v1.0/task-status/133?limit=10', $headers);
        $authHeaderBuilder = new AuthorizationHeaderBuilder($request, $this->authKey);
        $authHeaderBuilder->setRealm($realm);
        $authHeaderBuilder->setId('efdde334-fe7b-11e4-a322-1697f925ec7b');
        $authHeaderBuilder->setNonce('d1954337-5319-4821-8427-115542e08d10');
        $authHeader = $authHeaderBuilder->getAuthorizationHeader();

        $middleware = new MockHmacAuthMiddleware($this->authKey, $realm, $authHeader);

        $request = $middleware->signRequest($request);

        $expected = 'acquia-http-hmac realm="Pipet%20service",'
                    . 'id="efdde334-fe7b-11e4-a322-1697f925ec7b",'
                    . 'nonce="d1954337-5319-4821-8427-115542e08d10",'
                    . 'version="2.0",'
                    . 'headers="",'
                    . 'signature="MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc="';

        $this->assertEquals($expected, $request->getHeaderLine('Authorization'));
    }

    /**
     * Ensures the middleware throws an exception if the response is missing the right header.
     *
     * @expectedException \Acquia\Hmac\Exception\MalformedResponseException
     */
    public function testMissingRequiredResponseHeader()
    {
        $stack = new HandlerStack();
        $stack->setHandler(new MockHandler([new Response(200)]));
        $stack->push(new HmacAuthMiddleware($this->authKey));

        $client = new Client([
            'handler' => $stack,
        ]);

        $client->get('http://example.com');
    }

    /**
     * Ensures the middleware throws an exception if the response can't be authenticated.
     *
     * @expectedException \Acquia\Hmac\Exception\MalformedResponseException
     */
    public function testInauthenticResponse()
    {
        $headers = [
            'X-Server-Authorization-HMAC-SHA256' => 'bad-signature',
        ];

        $response = new Response(200, $headers);

        $stack = new HandlerStack();

        $stack->setHandler(new MockHandler([$response]));
        $stack->push(new HmacAuthMiddleware($this->authKey));

        $client = new Client([
            'handler' => $stack,
        ]);

        $client->get('http://example.com');
    }
    
    /**
     * Ensures the HTTP HMAC middleware registers correctly.
     */
    public function testRegisterPlugin()
    {
        $realm = 'Pipet service';

        $requestHeaders = [
            'X-Authorization-Timestamp' => '1432075982',
        ];

        $request = new Request('GET', 'https://example.acquiapipet.net/v1.0/task-status/133?limit=10', $requestHeaders);
        $authHeaderBuilder = new AuthorizationHeaderBuilder($request, $this->authKey);
        $authHeaderBuilder->setRealm($realm);
        $authHeaderBuilder->setId('efdde334-fe7b-11e4-a322-1697f925ec7b');
        $authHeaderBuilder->setNonce('d1954337-5319-4821-8427-115542e08d10');
        $authHeader = $authHeaderBuilder->getAuthorizationHeader();

        $middleware = new MockHmacAuthMiddleware($this->authKey, $realm, $authHeader);

        $container = [];
        $history = Middleware::history($container);

        $responseHeaders = [
            'X-Server-Authorization-HMAC-SHA256' => 'LusIUHmqt9NOALrQ4N4MtXZEFE03MjcDjziK+vVqhvQ=',
        ];

        $response = new Response(200, $responseHeaders);

        $stack = new HandlerStack();
        $stack->setHandler(new MockHandler([$response]));
        $stack->push($middleware);
        $stack->push($history);

        $client = new Client([
            'base_uri' => 'https://example.acquiapipet.net/',
            'handler' => $stack,
        ]);

        $client->send($request);

        $transaction = reset($container);
        $request = $transaction['request'];

        $expected = 'acquia-http-hmac realm="Pipet%20service",'
                    . 'id="efdde334-fe7b-11e4-a322-1697f925ec7b",'
                    . 'nonce="d1954337-5319-4821-8427-115542e08d10",'
                    . 'version="2.0",'
                    . 'headers="",'
                    . 'signature="MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc="';

        $this->assertEquals($expected, $request->getHeaderLine('Authorization'));
    }
}
