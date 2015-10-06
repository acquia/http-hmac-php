<?php

namespace Acquia\Hmac\Test;

use Acquia\Hmac\Request\Guzzle5;
use GuzzleHttp\Message\Request;
use GuzzleHttp\Stream\Stream;

class Guzzle5RequestTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @return \Acquia\Hmac\Request\Guzzle5
     */
    public function getRequest(array $headers = array(), $method = 'GET')
    {
        $uri = 'http://example.com/resource/1?key=value';
        return new Guzzle5(new Request($method, $uri, $headers));
    }

    public function testHasHeader()
    {
        if (!GuzzleVersionChecker::hasGuzzle5()) {
            $this->markTestSkipped('Guzzle5RequestTest requires Guzzle 5 compliant library.');
        }
        $request = $this->getRequest(array('header' => 'value'));

        $this->assertTrue($request->hasHeader('header'));
        $this->assertFalse($request->hasHeader('missing'));
    }

    public function testGetHeader()
    {
        if (!GuzzleVersionChecker::hasGuzzle5()) {
            $this->markTestSkipped('Guzzle5RequestTest requires Guzzle 5 compliant library.');
        }
        $request = $this->getRequest(array('header' => 'value'));
        $this->assertEquals('value', $request->getHeader('header'));
        $this->assertEmpty($request->getHeader('missing'));
    }

    public function testGetMethod()
    {
        if (!GuzzleVersionChecker::hasGuzzle5()) {
            $this->markTestSkipped('Guzzle5RequestTest requires Guzzle 5 compliant library.');
        }
        $request1 = $this->getRequest(array(), 'GET');
        $this->assertEquals('GET', $request1->getMethod());

        $request2 = $this->getRequest(array(), 'POST');
        $this->assertEquals('POST', $request2->getMethod());
    }

    public function testGetBody()
    {
        if (!GuzzleVersionChecker::hasGuzzle5()) {
            $this->markTestSkipped('Guzzle5RequestTest requires Guzzle 5 compliant library.');
        }
        $request1 = $this->getRequest();
        $this->assertEquals('', $request1->getBody());

        $guzzleRequest = new Request('GET', 'http://example.com');
        $stream = Stream::factory('test content');
        $guzzleRequest->setBody($stream);
        $request2 = new Guzzle5($guzzleRequest);
        $this->assertEquals('test content', $request2->getBody());
    }

    public function testGetResource()
    {
        if (!GuzzleVersionChecker::hasGuzzle5()) {
            $this->markTestSkipped('Guzzle5RequestTest requires Guzzle 5 compliant library.');
        }
        $request = $this->getRequest();
        $this->assertEquals('/resource/1?key=value', $request->getResource());
    }
}
