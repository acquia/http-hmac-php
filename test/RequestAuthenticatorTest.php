<?php

namespace Acquia\Hmac\Test;

use Acquia\Hmac\RequestAuthenticator;
use Acquia\Hmac\RequestSigner;
use GuzzleHttp\ClientInterface;

class RequestAuthenticatorTest extends \PHPUnit_Framework_TestCase
{
    public function testValidSignature()
    {
        $signer = new RequestSigner();
        $signer->addCustomHeader('Custom1');

        $request = new DummyRequest();
        $request->headers = array(
            'Content-Type' => 'text/plain',
            'Date' => 'Fri, 19 Mar 1982 00:00:04 GMT',
            'Authorization' => 'Acquia 1:' . DigestVersion1Test::EXPECTED_HASH,
            'Custom1' => 'Value1',
        );

        $authenticator = new RequestAuthenticator($signer, 0);
        $key = $authenticator->authenticate($request, new DummyKeyLoader());

        $this->assertInstanceOf('Acquia\Hmac\Test\DummyKey', $key);
        $this->assertEquals('1', $key->getId());
        $this->assertEquals('secret-key', $key->getSecret());
    }

    /**
     * @expectedException \Acquia\Hmac\Exception\InvalidSignatureException
     */
    public function testInvalidSignature()
    {
        $signer = new RequestSigner();
        $signer->addCustomHeader('Custom1');

        $request = new DummyRequest();
        $request->headers = array(
            'Content-Type' => 'text/plain',
            'Date' => 'Fri, 19 Mar 1982 00:00:04 GMT',
            'Authorization' => 'Acquia 1:badsignature',
            'Custom1' => 'Value1',
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
            'Date' => 'Fri, 19 Mar 1982 00:00:04 GMT',
            'Authorization' => 'Acquia 1:' . DigestVersion1Test::EXPECTED_HASH,
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
            'Date' => $time->format(ClientInterface::HTTP_DATE),
            'Authorization' => 'Acquia 1:' . DigestVersion1Test::EXPECTED_HASH,
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
            'Date' => 'Fri, 19 Mar 1982 00:00:04 GMT',
            'Authorization' => 'Acquia 2:' . DigestVersion1Test::EXPECTED_HASH,
        );

        $authenticator = new RequestAuthenticator(new RequestSigner(), 0);
        $authenticator->authenticate($request, new DummyKeyLoader());
    }
}
