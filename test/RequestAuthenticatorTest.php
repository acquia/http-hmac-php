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
        // @TODO 3.0 add custom headers into the message.
        //$signer->addCustomHeader('Custom1');

        $request = new DummyRequest();
        $request->headers = array(
            'Content-Type' => 'text/plain',
            'X-Authorization-Timestamp' => '1432075982',
            'Authorization' => 'acquia-http-hmac realm:"Pipet service",' . "\n"
            . 'id:"' . $this->auth_id . '",' . "\n"
            . 'nonce:"d1954337-5319-4821-8427-115542e08d10",' . "\n"
            . 'version:"2.0",' . "\n"
            . 'headers:"",' . "\n"
            . 'signature:"MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc="',
        );

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
        // @TODO 3.0 add custom headers into the message.
        //$signer->addCustomHeader('Custom1');

        $request = new DummyRequest();
        $request->headers = array(
            'Content-Type' => 'text/plain',
            'X-Authorization-Timestamp' => '1432075982',
            'Authorization' => 'acquia-http-hmac realm:"Pipet service",' . "\n"
            . 'id:"' . $this->auth_id . '",' . "\n"
            . 'nonce:"d1954337-5319-4821-8427-115542e08d10",' . "\n"
            . 'version:"2.0",' . "\n"
            . 'headers:"",' . "\n"
            . 'signature:"bRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc="',
        );

        $authenticator = new RequestAuthenticator($signer, 0);
        $authenticator->authenticate($request, new DummyKeyLoader());
    }

    /**
     * @expectedException \Acquia\Hmac\Exception\TimestampOutOfRangeException
     */
    public function testExpiredRequest()
    {
        $signer = new RequestSigner();

        $request = new DummyRequest();
        $request->headers = array(
            'Content-Type' => 'text/plain',
            'X-Authorization-Timestamp' => '1432075982',
            'Authorization' => 'acquia-http-hmac realm:"Pipet service",' . "\n"
            . 'id:"' . $this->auth_id . '",' . "\n"
            . 'nonce:"d1954337-5319-4821-8427-115542e08d10",' . "\n"
            . 'version:"2.0",' . "\n"
            . 'headers:"",' . "\n"
            . 'signature:"MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc="',
        );

        $authenticator = new RequestAuthenticator(new RequestSigner(), '10 minutes');
        $authenticator->authenticate($request, new DummyKeyLoader());
    }

    /**
     * @expectedException \Acquia\Hmac\Exception\TimestampOutOfRangeException
     */
    public function testFutureRequest()
    {
        $signer = new RequestSigner();
        $time = new \DateTime('+11 minutes');

        $request = new DummyRequest();
        $request->headers = array(
            'Content-Type' => 'text/plain',
            'X-Authorization-Timestamp' => '1232075982',
            'Authorization' => 'acquia-http-hmac realm:"Pipet service",' . "\n"
            . 'id:"' . $this->auth_id . '",' . "\n"
            . 'nonce:"d1954337-5319-4821-8427-115542e08d10",' . "\n"
            . 'version:"2.0",' . "\n"
            . 'headers:"",' . "\n"
            . 'signature:"MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc="',
        );

        $authenticator = new RequestAuthenticator(new RequestSigner(), '10 minutes');
        $authenticator->authenticate($request, new DummyKeyLoader());
    }

    /**
     * @expectedException \Acquia\Hmac\Exception\KeyNotFoundException
     */
    public function testKeyNotFound()
    {
        $signer = new RequestSigner();

        $request = new DummyRequest();
        $request->headers = array(
            'Content-Type' => 'text/plain',
            'X-Authorization-Timestamp' => '1232075982',
            'Authorization' => 'acquia-http-hmac realm:"Pipet service",' . "\n"
            . 'id:"bad-id",' . "\n"
            . 'nonce:"d1954337-5319-4821-8427-115542e08d10",' . "\n"
            . 'version:"2.0",' . "\n"
            . 'headers:"",' . "\n"
            . 'signature:"MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc="',
        );

        $authenticator = new RequestAuthenticator(new RequestSigner(), 0);
        $authenticator->authenticate($request, new DummyKeyLoader());
    }
}
