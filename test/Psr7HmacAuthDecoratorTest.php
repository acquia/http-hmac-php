<?php

namespace Acquia\Hmac\test;

use Acquia\Hmac\Psr7\HmacAuthDecorator;
use Acquia\Hmac\RequestSigner;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7;
use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Middleware;

class Psr7HmacAuthDecoratorTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @return \Acquia\Hmac\Psr7\HmacAuthDecorator
     */
    public function getDecorator()
    {
        $signer = new RequestSigner();
        $signer->addCustomHeader('Custom1');

        $decorator = new HmacAuthDecorator($signer, '1', 'secret-key');

        return $decorator;
    }

    public function testGetDefaultContentType()
    {
        $decorator = $this->getDecorator();
        $this->assertEquals('application/json; charset=utf-8', $decorator->getDefaultContentType());
    }

    public function testSetDefaultContentType()
    {
        $decorator = $this->getDecorator();
        $decorator->setDefaultContentType('text/plain');
        $this->assertEquals('text/plain', $decorator->getDefaultContentType());
    }

    public function testSetDefaultContentTypeHeader()
    {
        $decorator = $this->getDecorator();
        $decorator->setDefaultContentType('some/content-type');

        $uri = 'http://example.com/resource/1?key=value';
        $request = new Request('GET', $uri, array());

        $d = $decorator($request);
        $this->assertEquals('some/content-type', $d->getHeader('Content-Type')[0]);
    }

    public function testSetDefaultDateHeader()
    {
        $decorator = $this->getDecorator();

        $uri = 'http://example.com/resource/1?key=value';
        $request = new Request('GET', $uri, array());

        $d = $decorator($request);

        $date = $d->getHeader('Date')[0];
        $timestamp = strtotime($date);

        // It shouldn't take this test 10 seconds to run, but pad it since we
        // can not assume the time will be exactly the same.
        $difference = time() - $timestamp;
        $this->assertTrue($difference > -10);
        $this->assertTrue($difference < 10);
    }

    public function testAuthorizationHeader()
    {
        $decorator = $this->getDecorator();

        $uri = 'http://example.com/resource/1?key=value';
        $request = new Request('GET', $uri, array(
            'Content-Type' => 'text/plain',
            'Date' => 'Fri, 19 Mar 1982 00:00:04 GMT',
            'Custom1' => 'Value1',
        ));

        $stream = Psr7\stream_for('test content');
        $request = $request->withBody($stream);

        $d = $decorator($request);

        $expected = 'Acquia 1:/aZkY8OkLv29aI+F+sSOsDE0VIk=';
        $this->assertEquals($expected, (string) $d->getHeader('Authorization')[0]);
    }

    public function testAddDecoratorToStack()
    {
        $uri = '/resource/1?key=value';
        $request = new Request('GET', $uri, array(
            'Content-Type' => 'text/plain',
            'Date' => 'Fri, 19 Mar 1982 00:00:04 GMT',
            'Custom1' => 'Value1',
        ));

        $container = [];
        $history = Middleware::history($container);

        // // Create a mock and queue two responses.
        $mock = new MockHandler([
            new Response(200, ['X-Foo' => 'Bar']),
        ]);

        $decorator  = $this->getDecorator();

        $stack = HandlerStack::create($mock); // Wrap w/ middleware
        $stack->push(Middleware::mapRequest($decorator));
        $stack->push($history);

        $client = new Client(['base_url' => 'http://example.com', 'handler' => $stack]);
        $client->send($request);
        $request = $container[0]['request'];
        $authorization = (string) $request->getHeader('Authorization')[0];
        $this->assertRegExp('@Acquia 1:([a-zA-Z0-9+/]+={0,2})$@', $authorization);
    }
}
