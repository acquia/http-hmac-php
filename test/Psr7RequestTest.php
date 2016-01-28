<?php

namespace Acquia\Hmac\Test;

use Acquia\Hmac\Request\Psr7;
use GuzzleHttp\Psr7\Request;

class Psr7RequestTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @return \Acquia\Hmac\Request\Psr7
     */
    public function getRequest(array $headers = array(), $method = 'GET')
    {
        $uri = 'http://example.com/resource/1?key=value';
        return new Psr7(new Request($method, $uri, $headers));
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

        $request2 = new Psr7(new Request('GET', 'http://example.com', [], 'test content'));
        $this->assertEquals('test content', $request2->getBody());
    }

    public function testGetResource()
    {
        $request = $this->getRequest();
        $this->assertEquals('/resource/1?key=value', $request->getResource());
    }
}
