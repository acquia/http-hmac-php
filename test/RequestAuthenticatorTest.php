<?php

namespace Acquia\Hmac\Test;

use Acquia\Hmac\RequestAuthenticator;
use Acquia\Hmac\RequestSigner;

class RequestAuthenticatorTest extends \PHPUnit_Framework_TestCase
{

    protected $auth_id;

    protected $auth_secret;

    /**
     * @var array
     *   A set of sample key-secret pairs for testing.
     */
    protected $keys;

    /**
     * {@inheritDoc}
     */
    protected function setUp()
    {
        $this->keys = [
            'efdde334-fe7b-11e4-a322-1697f925ec7b' => 'W5PeGMxSItNerkNFqQMfYiJvH14WzVJMy54CPoTAYoI=',
            '615d6517-1cea-4aa3-b48e-96d83c16c4dd' => 'TXkgU2VjcmV0IEtleSBUaGF0IGlzIFZlcnkgU2VjdXJl',
        ];
    }

    public function testValidSignature()
    {
        $auth_secret = reset($this->keys);
        $auth_id = key($this->keys);

        $signer = new RequestSigner();
        $signer->setTimestamp(1432075982);

        $headers = [
            'Content-Type' => 'text/plain',
            'X-Authorization-Timestamp' => '1432075982',
            'Authorization' => 'acquia-http-hmac realm="Pipet service",'
            . 'id="' . $auth_id . '",'
            . 'nonce="d1954337-5319-4821-8427-115542e08d10",'
            . 'version="2.0",'
            . 'headers="",'
            . 'signature="MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc="',
        ];
        $request = DummyRequest::generate('GET', 'https://example.acquiapipet.net', '/v1.0/task-status/133', 'limit=10', $headers);

        $authenticator = new RequestAuthenticator($signer, 0);
        $key = $authenticator->authenticate($request, new DummyKeyLoader($this->keys));

        $this->assertInstanceOf('Acquia\Hmac\Test\DummyKey', $key);
        $this->assertEquals($auth_id, $key->getId());
        $this->assertEquals($auth_secret, $key->getSecret());
    }

    /**
     * @expectedException \Acquia\Hmac\Exception\InvalidSignatureException
     */
    public function testInvalidSignature()
    {
        $auth_id = key($this->keys);

        $signer = new RequestSigner();

        $headers = [
            'Content-Type' => 'text/plain',
            'X-Authorization-Timestamp' => '1432075982',
            'Authorization' => 'acquia-http-hmac realm="Pipet service",'
            . 'id="' . $auth_id . '",'
            . 'nonce="d1954337-5319-4821-8427-115542e08d10",'
            . 'version="2.0",'
            . 'headers="",'
            . 'signature="bRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc="',
        ];
        $request = DummyRequest::generate('GET', 'https://example.com', '/test', '', $headers);

        $authenticator = new RequestAuthenticator($signer, 0);
        $authenticator->authenticate($request, new DummyKeyLoader($this->keys));
    }

    /**
     * @expectedException \Acquia\Hmac\Exception\TimestampOutOfRangeException
     */
    public function testExpiredRequest()
    {
        $auth_id = key($this->keys);

        $signer = new RequestSigner();
        $signer->setTimestamp(1432075982);

        $headers = [
            'Content-Type' => 'text/plain',
            'X-Authorization-Timestamp' => '1432075982',
            'Authorization' => 'acquia-http-hmac realm="Pipet service",'
            . 'id="' . $auth_id . '",'
            . 'nonce="d1954337-5319-4821-8427-115542e08d10",'
            . 'version="2.0",'
            . 'headers="",'
            . 'signature="MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc="',
        ];
        $request = DummyRequest::generate('GET', 'https://example.com', '/test', '', $headers);

        $authenticator = new RequestAuthenticator($signer, '10 minutes');
        $authenticator->authenticate($request, new DummyKeyLoader($this->keys));
    }

    /**
     * @expectedException \Acquia\Hmac\Exception\TimestampOutOfRangeException
     */
    public function testFutureRequest()
    {
        $auth_id = key($this->keys);

        $time = new \DateTime('+11 minutes');
        $timestamp = (string) $time->getTimestamp();

        $signer = new RequestSigner();
        $signer->setTimestamp($timestamp);

        $headers = [
            'Content-Type' => 'text/plain',
            'X-Authorization-Timestamp' => $timestamp,
            'Authorization' => 'acquia-http-hmac realm="Pipet service",'
            . 'id="' . $auth_id . '",'
            . 'nonce="d1954337-5319-4821-8427-115542e08d10",'
            . 'version="2.0",'
            . 'headers="",'
            . 'signature="MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc="',
        ];
        $request = DummyRequest::generate('GET', 'https://example.com', '/test', '', $headers);

        $authenticator = new RequestAuthenticator($signer, '10 minutes');
        $authenticator->authenticate($request, new DummyKeyLoader($this->keys));
    }

    /**
     * @expectedException \Acquia\Hmac\Exception\KeyNotFoundException
     */
    public function testKeyNotFound()
    {
        $signer = new RequestSigner();

        $headers = [
            'Content-Type' => 'text/plain',
            'X-Authorization-Timestamp' => '1232075982',
            'Authorization' => 'acquia-http-hmac realm="Pipet service",'
            . 'id="bad-id",'
            . 'nonce="d1954337-5319-4821-8427-115542e08d10",'
            . 'version="2.0",'
            . 'headers="",'
            . 'signature="MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc="',
        ];
        $request = DummyRequest::generate('GET', 'https://example.com', '/test', '', $headers);

        $authenticator = new RequestAuthenticator($signer, 0);
        $authenticator->authenticate($request, new DummyKeyLoader($this->keys));
    }
}
