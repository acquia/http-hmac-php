<?php

namespace Acquia\Hmac\Test;

use Acquia\Hmac\RequestAuthenticator;
use Acquia\Hmac\RequestSigner;

class RequestAuthenticatorTest extends \PHPUnit_Framework_TestCase
{

    protected $auth_id;

    protected $auth_secret;

    protected function setUp()
    {
        $this->auth_id = 'efdde334-fe7b-11e4-a322-1697f925ec7b';
        $this->auth_secret = 'W5PeGMxSItNerkNFqQMfYiJvH14WzVJMy54CPoTAYoI=';
    }

    public function testValidSignature()
    {
        $signer = new RequestSigner();
        $signer->setTimestamp(1432075982);

        $headers = array(
            'Content-Type' => 'text/plain',
            'X-Authorization-Timestamp' => '1432075982',
            'Authorization' => 'acquia-http-hmac realm="Pipet service",'
            . 'id="' . $this->auth_id . '",'
            . 'nonce="d1954337-5319-4821-8427-115542e08d10",'
            . 'version="2.0",'
            . 'headers="",'
            . 'signature="MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc="',
        );
        $request = DummyRequest::generate('GET', 'https://example.acquiapipet.net', '/v1.0/task-status/133', 'limit=10', $headers);

        $authenticator = new RequestAuthenticator($signer, 0);
        $key = $authenticator->authenticate($request, new DummyKeyLoader());

        $this->assertInstanceOf('Acquia\Hmac\Test\DummyKey', $key);
        $this->assertEquals($this->auth_id, $key->getId());
        $this->assertEquals($this->auth_secret, $key->getSecret());
    }

    /**
     * @expectedException \Acquia\Hmac\Exception\InvalidSignatureException
     */
    public function testInvalidSignature()
    {
        $signer = new RequestSigner();

        $headers = array(
            'Content-Type' => 'text/plain',
            'X-Authorization-Timestamp' => '1432075982',
            'Authorization' => 'acquia-http-hmac realm="Pipet service",'
            . 'id="' . $this->auth_id . '",'
            . 'nonce="d1954337-5319-4821-8427-115542e08d10",'
            . 'version="2.0",'
            . 'headers="",'
            . 'signature="bRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc="',
        );
        $request = DummyRequest::generate('GET', 'https://example.com', '/test', '', $headers);

        $authenticator = new RequestAuthenticator($signer, 0);
        $authenticator->authenticate($request, new DummyKeyLoader());
    }

    /**
     * @expectedException \Acquia\Hmac\Exception\TimestampOutOfRangeException
     */
    public function testExpiredRequest()
    {
        $signer = new RequestSigner();
        $signer->setTimestamp(1432075982);

        $headers = array(
            'Content-Type' => 'text/plain',
            'X-Authorization-Timestamp' => '1432075982',
            'Authorization' => 'acquia-http-hmac realm="Pipet service",'
            . 'id="' . $this->auth_id . '",'
            . 'nonce="d1954337-5319-4821-8427-115542e08d10",'
            . 'version="2.0",'
            . 'headers="",'
            . 'signature="MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc="',
        );
        $request = DummyRequest::generate('GET', 'https://example.com', '/test', '', $headers);

        $authenticator = new RequestAuthenticator($signer, '10 minutes');
        $authenticator->authenticate($request, new DummyKeyLoader());
    }

    /**
     * @expectedException \Acquia\Hmac\Exception\TimestampOutOfRangeException
     */
    public function testFutureRequest()
    {
        $time = new \DateTime('+11 minutes');
        $timestamp = (string) $time->getTimestamp();

        $signer = new RequestSigner();
        $signer->setTimestamp($timestamp);

        $headers = array(
            'Content-Type' => 'text/plain',
            'X-Authorization-Timestamp' => $timestamp,
            'Authorization' => 'acquia-http-hmac realm="Pipet service",'
            . 'id="' . $this->auth_id . '",'
            . 'nonce="d1954337-5319-4821-8427-115542e08d10",'
            . 'version="2.0",'
            . 'headers="",'
            . 'signature="MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc="',
        );
        $request = DummyRequest::generate('GET', 'https://example.com', '/test', '', $headers);

        $authenticator = new RequestAuthenticator($signer, '10 minutes');
        $authenticator->authenticate($request, new DummyKeyLoader());
    }

    /**
     * @expectedException \Acquia\Hmac\Exception\KeyNotFoundException
     */
    public function testKeyNotFound()
    {
        $signer = new RequestSigner();

        $headers = array(
            'Content-Type' => 'text/plain',
            'X-Authorization-Timestamp' => '1232075982',
            'Authorization' => 'acquia-http-hmac realm="Pipet service",'
            . 'id="bad-id",'
            . 'nonce="d1954337-5319-4821-8427-115542e08d10",'
            . 'version="2.0",'
            . 'headers="",'
            . 'signature="MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc="',
        );
        $request = DummyRequest::generate('GET', 'https://example.com', '/test', '', $headers);

        $authenticator = new RequestAuthenticator(new RequestSigner(), 0);
        $authenticator->authenticate($request, new DummyKeyLoader());
    }
}
