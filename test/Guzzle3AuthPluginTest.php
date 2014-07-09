<?php

namespace Acquia\Hmac\Test;

use Acquia\Hmac\Guzzle3\HmacAuthPlugin;
use Acquia\Hmac\RequestSigner;
use Guzzle\Http\Client;
use Guzzle\Http\Message\Request;
use Guzzle\Http\Message\EntityEnclosingRequest;
use Guzzle\Http\Message\Response;
use Guzzle\Plugin\Mock\MockPlugin;

class Guzzle3AuthPluginTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @return \Acquia\Hmac\Guzzle3\HmacAuthPlugin
     */
    public function getPlugin()
    {
        $signer = new RequestSigner();
        $signer->addCustomHeader('Custom1');

        $plugin = new HmacAuthPlugin($signer, '1', 'secret-key');
        return $plugin;
    }

    public function testGetDefaultContentType()
    {
        $plugin = $this->getPlugin();
        $this->assertEquals('application/json; charset=utf-8', $plugin->getDefaultContentType());
    }

    public function testSetDefaultContentType()
    {
        $plugin = $this->getPlugin();
        $plugin->setDefaultContentType('text/plain');
        $this->assertEquals('text/plain', $plugin->getDefaultContentType());
    }

    public function testSetDefaultContentTypeHeader()
    {
        $plugin = $this->getPlugin();
        $plugin->setDefaultContentType('some/content-type');

        $uri = 'http://example.com/resource/1?key=value';
        $request = new Request('GET', $uri, array());

        $plugin->signRequest($request);
        $this->assertEquals('some/content-type', $request->getHeader('Content-Type'));
    }

    public function testSetDefaultDateHeader()
    {
        $plugin = $this->getPlugin();

        $uri = 'http://example.com/resource/1?key=value';
        $request = new Request('GET', $uri, array());

        $plugin->signRequest($request);

        $date = $request->getHeader('Date');
        $timestamp = strtotime($date);

        // It shouldn't take this test 10 seconds to run, but pad it since we
        // can not assume the time will be exactly the same.
        $difference = time() - $timestamp;
        $this->assertTrue($difference > -10);
        $this->assertTrue($difference < 10);
    }

    public function testAuthorizationHeader()
    {
        $plugin = $this->getPlugin();

        $uri = 'http://example.com/resource/1?key=value';
        $request = new EntityEnclosingRequest('GET', $uri, array(
            'Content-Type' => 'text/plain',
            'Date' => 'Fri, 19 Mar 1982 00:00:04 GMT',
            'Custom1' => 'Value1',
        ));
        $request->setBody('test content');

        $plugin->signRequest($request);

        $expected = 'Acquia 1:' . DigestVersion1Test::EXPECTED_HASH;
        $this->assertEquals($expected, (string) $request->getHeader('Authorization'));
    }

    public function testRegisterPlugin()
    {
        $client = new Client('http://example.com');
        $client->addSubscriber($this->getPlugin());

        $mock = new MockPlugin();
        $mock->addResponse(new Response(200));
        $client->addSubscriber($mock);

        $request = $client->get('/resource/1');
        $request->send();

        $authorization = (string) $request->getHeader('Authorization');
        $this->assertRegExp('@Acquia 1:([a-zA-Z0-9+/]+={0,2})$@', $authorization);
    }
}
