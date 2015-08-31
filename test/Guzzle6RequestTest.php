<?php

namespace Acquia\Hmac\test;

use Acquia\Hmac\Request\Guzzle6;
use GuzzleHttp\Psr7\Request;

class Guzzle6RequestTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @return \Acquia\Hmac\Request\Guzzle6
     */
    public function getRequest(array $headers = array(), $method = 'GET')
    {
        $uri = 'http://example.com/resource/1?key=value';

        return new Guzzle6(new Request($method, $uri, $headers));
    }

    public function testHasHeader()
    {
        if (!GuzzleVersionChecker::hasGuzzle6()) {
            $this->markTestSkipped('Guzzle6RequestTest requires Guzzle 6 compliant library.');
        }
        $request = $this->getRequest(array('header' => 'value'));

        $this->assertTrue($request->hasHeader('header'));
        $this->assertFalse($request->hasHeader('missing'));
    }

    public function testGetHeader()
    {
        if (!GuzzleVersionChecker::hasGuzzle6()) {
            $this->markTestSkipped('Guzzle6RequestTest requires Guzzle 6 compliant library.');
        }
        $request = $this->getRequest(array('header' => 'value'));
        $this->assertEquals('value', $request->getHeader('header'));
        $this->assertEmpty($request->getHeader('missing'));
    }

    public function testGetMethod()
    {
        if (!GuzzleVersionChecker::hasGuzzle6()) {
            $this->markTestSkipped('Guzzle6RequestTest requires Guzzle 6 compliant library.');
        }
        $request1 = $this->getRequest(array(), 'GET');
        $this->assertEquals('GET', $request1->getMethod());

        $request2 = $this->getRequest(array(), 'POST');
        $this->assertEquals('POST', $request2->getMethod());
    }

    public function testGetBody()
    {
        if (!GuzzleVersionChecker::hasGuzzle6()) {
            $this->markTestSkipped('Guzzle6RequestTest requires Guzzle 6 compliant library.');
        }
        $request1 = $this->getRequest();
        $this->assertEquals('', $request1->getBody());

        $guzzleRequest = new Request('GET', 'http://example.com', [], 'test content');
        $request2 = new Guzzle6($guzzleRequest);
        $this->assertEquals('test content', $request2->getBody());
    }

    public function testGetResource()
    {
        if (!GuzzleVersionChecker::hasGuzzle6()) {
            $this->markTestSkipped('Guzzle6RequestTest requires Guzzle 6 compliant library.');
        }
        $request = $this->getRequest();
        $this->assertEquals('/resource/1?key=value', $request->getResource());
    }
}
