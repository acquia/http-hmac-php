<?php

namespace Acquia\Hmac\Test;

use Acquia\Hmac\Guzzle5\HmacAuthPlugin;
use Acquia\Hmac\RequestSigner;
use GuzzleHttp\Client;
use GuzzleHttp\Message\Request;
use GuzzleHttp\Message\Response;
use GuzzleHttp\Subscriber\Mock;
use GuzzleHttp\Stream\Stream;

class Guzzle5AuthPluginTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @return \Acquia\Hmac\Guzzle5\HmacAuthPlugin
     */
    public function getPlugin()
    {
        if (!GuzzleVersionChecker::hasGuzzle5()) {
            $this->markTestSkipped('Guzzle5AuthPluginText requires Guzzle 5 compliant library.');
        }
        $signer = new RequestSigner();
        $signer->addCustomHeader('Custom1');

        $plugin = new HmacAuthPlugin($signer, '1', 'secret-key');
        return $plugin;
    }

    public function testGetDefaultContentType()
    {
        if (!GuzzleVersionChecker::hasGuzzle5()) {
            $this->markTestSkipped('Guzzle5AuthPluginText requires Guzzle 5 compliant library.');
        }
        $plugin = $this->getPlugin();
        $this->assertEquals('application/json; charset=utf-8', $plugin->getDefaultContentType());
    }

    public function testSetDefaultContentType()
    {
        if (!GuzzleVersionChecker::hasGuzzle5()) {
            $this->markTestSkipped('Guzzle5AuthPluginText requires Guzzle 5 compliant library.');
        }
        $plugin = $this->getPlugin();
        $plugin->setDefaultContentType('text/plain');
        $this->assertEquals('text/plain', $plugin->getDefaultContentType());
    }

    public function testSetDefaultContentTypeHeader()
    {
        if (!GuzzleVersionChecker::hasGuzzle5()) {
            $this->markTestSkipped('Guzzle5AuthPluginText requires Guzzle 5 compliant library.');
        }
        $plugin = $this->getPlugin();
        $plugin->setDefaultContentType('some/content-type');

        $uri = 'http://example.com/resource/1?key=value';
        $request = new Request('GET', $uri, array());

        $plugin->signRequest($request);
        $this->assertEquals('some/content-type', $request->getHeader('Content-Type'));
    }

    public function testSetDefaultDateHeader()
    {
        if (!GuzzleVersionChecker::hasGuzzle5()) {
            $this->markTestSkipped('Guzzle5AuthPluginText requires Guzzle 5 compliant library.');
        }
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
        if (!GuzzleVersionChecker::hasGuzzle5()) {
            $this->markTestSkipped('Guzzle5AuthPluginText requires Guzzle 5 compliant library.');
        }
        $plugin = $this->getPlugin();

        $uri = 'http://example.com/resource/1?key=value';
        $request = new Request('GET', $uri, array(
            'Content-Type' => 'text/plain',
            'Date' => 'Fri, 19 Mar 1982 00:00:04 GMT',
            'Custom1' => 'Value1',
        ));
        $stream = Stream::factory('test content');
        $request->setBody($stream);

        $plugin->signRequest($request);

        $expected = 'Acquia 1:' . DigestVersion1Test::EXPECTED_HASH;
        $this->assertEquals($expected, (string) $request->getHeader('Authorization'));
    }

    public function testRegisterPlugin()
    {
        if (!GuzzleVersionChecker::hasGuzzle5()) {
            $this->markTestSkipped('Guzzle5AuthPluginText requires Guzzle 5 compliant library.');
        }
        $client = new Client(['base_url' => 'http://example.com']);
        $client->getEmitter()->attach($this->getPlugin());

        $mock = new Mock();
        $mock->addResponse(new Response(200));
        $client->getEmitter()->attach($mock);

        $request = $client->createRequest('GET', '/resource/1');
        $client->send($request);

        $authorization = (string) $request->getHeader('Authorization');
        $this->assertRegExp('@Acquia 1:([a-zA-Z0-9+/]+={0,2})$@', $authorization);
    }
}
