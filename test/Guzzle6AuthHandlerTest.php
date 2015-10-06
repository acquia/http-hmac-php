<?php

namespace Acquia\Hmac\Test;

use Acquia\Hmac\Guzzle6\HmacAuthHandler;
use Acquia\Hmac\RequestSigner;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;

class Guzzle6AuthHandlerTest extends \PHPUnit_Framework_TestCase
{
  public $test_id = '1';
  public $test_secret_key = 'secret-key';

  /**
   * @return \Acquia\Hmac\RequestSigner;
   */
  public function getSigner()
  {
    $signer = new RequestSigner();
    $signer->addCustomHeader('Custom1');

    return $signer;
  }

  /**
   * @return \Acquia\Hmac\Guzzle6\HmacAuthHandler
   */
  public function getHandler()
  {
    $signer = $this->getSigner();
    $handler = new HmacAuthHandler($signer, $this->test_id, $this->test_secret_key);

    return $handler;
  }

  public function testGetDefaultContentType()
  {
    if (!GuzzleVersionChecker::hasGuzzle6()) {
      $this->markTestSkipped('Guzzle6AuthHandlerTest requires Guzzle 6 compliant library.');
    }
    $handler = $this->getHandler();
    $this->assertEquals('application/json; charset=utf-8', $handler->getDefaultContentType());
  }

  public function testSetDefaultContentType()
  {
    if (!GuzzleVersionChecker::hasGuzzle6()) {
      $this->markTestSkipped('Guzzle6AuthHandlerTest requires Guzzle 6 compliant library.');
    }
    $handler = $this->getHandler();
    $handler->setDefaultContentType('text/plain');
    $this->assertEquals('text/plain', $handler->getDefaultContentType());
  }

  public function testSetDefaultContentTypeHeader()
  {
    if (!GuzzleVersionChecker::hasGuzzle6()) {
      $this->markTestSkipped('Guzzle6AuthHandlerTest requires Guzzle 6 compliant library.');
    }
    $handler = $this->getHandler();
    $handler->setDefaultContentType('some/content-type');

    $uri = 'http://example.com/resource/1?key=value';
    $request = new Request('GET', $uri, array());

    $request = $handler->signRequest($request);
    $header = $request->getHeader('Content-Type');
    $this->assertEquals('some/content-type', reset($header));
  }

  public function testSetDefaultDateHeader()
  {
    if (!GuzzleVersionChecker::hasGuzzle6()) {
      $this->markTestSkipped('Guzzle6AuthHandlerTest requires Guzzle 6 compliant library.');
    }
    $handler = $this->getHandler();

    $uri = 'http://example.com/resource/1?key=value';
    $request = new Request('GET', $uri, array());

    $request = $handler->signRequest($request);

    $date = $request->getHeader('Date');
    $timestamp = strtotime(reset($date));

    // It shouldn't take this test 10 seconds to run, but pad it since we
    // can not assume the time will be exactly the same.
    $difference = time() - $timestamp;
    $this->assertTrue($difference > -10);
    $this->assertTrue($difference < 10);
  }

  public function testAuthorizationHeader()
  {
    if (!GuzzleVersionChecker::hasGuzzle6()) {
      $this->markTestSkipped('Guzzle6AuthHandlerTest requires Guzzle 6 compliant library.');
    }
    $handler = $this->getHandler();

    $uri = 'http://example.com/resource/1?key=value';
    $request = new Request('GET', $uri, array(
      'Content-Type' => 'text/plain',
      'Date' => 'Fri, 19 Mar 1982 00:00:04 GMT',
      'Custom1' => 'Value1',
    ), 'test content');

    $request = $handler->signRequest($request);

    $expected = 'Acquia 1:'.DigestVersion1Test::EXPECTED_HASH;
    $auth_header = $request->getHeader('Authorization');
    $this->assertEquals($expected, reset($auth_header));
  }

  public function testRegisterHandler()
  {
    if (!GuzzleVersionChecker::hasGuzzle6()) {
      $this->markTestSkipped('Guzzle6AuthHandlerTest requires Guzzle 6 compliant library.');
    }
    $container = [];
    $history = Middleware::history($container);

    $mock = new MockHandler([
      new Response(200),
    ]);
    $signer = new RequestSigner();
    $stack = HmacAuthHandler::createWithMiddleware($signer, $this->test_id, $this->test_secret_key, $mock);
    $stack->push($history);
    $client = new Client(['handler' => $stack, 'base_url' => 'http://example.com']);
    $request = new Request('GET', '/resource/1');
    $client->send($request);

    $transaction = reset($container);
    $request = $transaction['request'];

    $authorization = $request->getHeader('Authorization');
    $this->assertRegExp('@Acquia 1:([a-zA-Z0-9+/]+={0,2})$@', reset($authorization));
  }
}
