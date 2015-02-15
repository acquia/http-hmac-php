<?php

namespace Acquia\Hmac\Test;

use Acquia\Hmac\Request\Guzzle3;
use Guzzle\Http\Message\Request;
use Guzzle\Http\Message\EntityEnclosingRequest;

class Guzzle3RequestTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @return \Acquia\Hmac\Request\Guzzle3
     */
    public function getRequest(array $headers = array(), $method = 'GET')
    {
        $uri = 'http://example.com/resource/1?key=value';
        return new Guzzle3(new Request($method, $uri, $headers));
    }

    public function testHasHeader()
    {
        $request = $this->getRequest(array('header' => 'value'));

        $this->assertTrue($request->hasHeader('header'));
        $this->assertFalse($request->hasHeader('missing'));
    }

    public function testGetHeader()
    {
        $request = $this->getRequest(array('header' => 'value'));
        $this->assertEquals('value', $request->getHeader('header'));
        $this->assertEmpty($request->getHeader('missing'));
    }

    public function testGetMethod()
    {
        $request1 = $this->getRequest(array(), 'GET');
        $this->assertEquals('GET', $request1->getMethod());

        $request2 = $this->getRequest(array(), 'POST');
        $this->assertEquals('POST', $request2->getMethod());
    }

    public function testGetBody()
    {
        $request1 = $this->getRequest();
        $this->assertEquals('', $request1->getBody());

        $guzzleRequest = new EntityEnclosingRequest('GET', 'http://example.com');
        $guzzleRequest->setBody('test content');
        $request2 = new Guzzle3($guzzleRequest);
        $this->assertEquals('test content', $request2->getBody());
    }

    public function testGetResource()
    {
        $request = $this->getRequest();
        $this->assertEquals('/resource/1?key=value', $request->getResource());
    }
}
