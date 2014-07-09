<?php

namespace Acquia\Hmac\Test;

use Acquia\Hmac\Request\Symfony;
use Symfony\Component\HttpFoundation\Request;

class SymfonyRequestTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @return \Acquia\Hmac\Request\Guzzle3
     */
    public function getRequest(array $headers = array(), $method = 'GET', $body = null)
    {
        $query = array('key' => 'value');

        $server = array(
            'REQUEST_METHOD' => $method,
            'REQUEST_URI' => '/resource/1?key=value',
        );

        foreach ($headers as $header => $value) {
            $server['HTTP_' . $header] = $value;
        }

        return new Symfony(new Request($query, array(), array(), array(), array(), $server, $body));
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

        $request2 = $this->getRequest(array(), 'GET', 'test content');
        $this->assertEquals('test content', $request2->getBody());
    }

    public function testGetResource()
    {
        $request = $this->getRequest();
        $this->assertEquals('/resource/1?key=value', $request->getResource());
    }
}
