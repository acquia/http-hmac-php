<?php

namespace Acquia\Hmac\Test;

use Acquia\Hmac\Guzzle\HmacAuthMiddleware;
use Acquia\Hmac\RequestSigner;
use GuzzleHttp\Client;
use GuzzleHttp\Message\Request;
use GuzzleHttp\Message\Response;
use GuzzleHttp\Subscriber\Mock;
use GuzzleHttp\Stream\Stream;

class GuzzleAuthMiddlewareTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @return \Acquia\Hmac\Guzzle\HmacAuthMiddleware
     */
    public function getMiddleware()
    {
        $signer = new RequestSigner();
        $signer->addCustomHeader('Custom1');

        $middleware = new HmacAuthMiddleware($signer, '1', 'secret-key');
        return $middleware;
    }

    public function testGetDefaultContentType()
    {
        $middleware = $this->getMiddleware();
        $this->assertEquals('application/json; charset=utf-8', $middleware->getDefaultContentType());
    }

    public function testSetDefaultContentType()
    {
        $middleware = $this->getMiddleware();
        $middleware->setDefaultContentType('text/plain');
        $this->assertEquals('text/plain', $middleware->getDefaultContentType());
    }
}