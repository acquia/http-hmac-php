<?php

namespace Acquia\Hmac\Test;

use Acquia\Hmac\AuthorizationHeader;
use Acquia\Hmac\Exception\MalformedRequestException;
use Acquia\Hmac\KeyInterface;
use Acquia\Hmac\RequestAuthenticator;
use Acquia\Hmac\Test\Mocks\MockKeyLoader;
use Acquia\Hmac\Test\Mocks\MockRequestAuthenticator;
use GuzzleHttp\Psr7\Request;
use PHPUnit\Framework\TestCase;

class RequestAuthenticatorTest extends TestCase
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

    /**
     * Ensures a valid request with a valid signature authenticates correctly.
     */
    public function testValidSignature()
    {
        $authId = key($this->keys);
        $authSecret = reset($this->keys);
        $timestamp = 1432075982;

        $headers = [
            'Content-Type' => 'text/plain',
            'X-Authorization-Timestamp' => $timestamp,
            'Authorization' => 'acquia-http-hmac realm="Pipet service",'
                . 'id="' . $authId . '",'
                . 'nonce="d1954337-5319-4821-8427-115542e08d10",'
                . 'version="2.0",'
                . 'headers="",'
                . 'signature="MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc="',
        ];
        $request = new Request(
            'GET',
            'https://example.acquiapipet.net/v1.0/task-status/133?limit=10',
            $headers
        );

        $authenticator = new MockRequestAuthenticator(
            new MockKeyLoader($this->keys),
            null,
            $timestamp
        );

        $key = $authenticator->authenticate($request);

        $this->assertInstanceOf(KeyInterface::class, $key);
        $this->assertEquals($authId, $key->getId());
        $this->assertEquals($authSecret, $key->getSecret());
    }

    /**
     * Ensures an exception is thrown if the signature is invalid.
     *
     * @expectedException \Acquia\Hmac\Exception\InvalidSignatureException
     */
    public function testInvalidSignature()
    {
        $realm = 'Pipet service';
        $id = key($this->keys);
        $nonce = 'd1954337-5319-4821-8427-115542e08d10';
        $version = '2.0';
        $headers = [];

        $headers = [
            'Content-Type' => 'text/plain',
            'X-Authorization-Timestamp' => time(),
            'Authorization' => 'acquia-http-hmac realm="' . $realm . '",'
                . 'id="' . $id . '",'
                . 'nonce="' . $nonce . '",'
                . 'version="' . $version . '",'
                . 'headers="' . implode(';', $headers) . '",'
                . 'signature="bRlPr/Z1WQz2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc="',
        ];
        $request = new Request('GET', 'https://example.com/test', $headers);

        $authHeader = new AuthorizationHeader(
            $realm,
            $id,
            $nonce,
            $version,
            $headers,
            'bad-sig'
        );

        $authenticator = new MockRequestAuthenticator(
            new MockKeyLoader($this->keys),
            $authHeader
        );
        $authenticator->authenticate($request);
    }

    /**
     * Ensures an exception is thrown if the request has expired.
     *
     * @expectedException \Acquia\Hmac\Exception\TimestampOutOfRangeException
     */
    public function testExpiredRequest()
    {
        $authId = key($this->keys);

        $headers = [
            'Content-Type' => 'text/plain',
            'X-Authorization-Timestamp' => 1,
            'Authorization' => 'acquia-http-hmac realm="Pipet service",'
                . 'id="' . $authId . '",'
                . 'nonce="d1954337-5319-4821-8427-115542e08d10",'
                . 'version="2.0",'
                . 'headers="",'
                . 'signature="bRlPr/Z1WQz2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc="',
        ];
        $request = new Request('GET', 'https://example.com/test', $headers);
        $authHeader = AuthorizationHeader::createFromRequest($request);

        $authenticator = new MockRequestAuthenticator(
            new MockKeyLoader($this->keys),
            $authHeader
        );
        $authenticator->authenticate($request);
    }

    /**
     * Ensures an exception is thrown if the request is from the far future.
     *
     * @expectedException \Acquia\Hmac\Exception\TimestampOutOfRangeException
     */
    public function testFutureRequest()
    {
        $auth_id = key($this->keys);

        $time = new \DateTime('+16 minutes');
        $timestamp = (string) $time->getTimestamp();

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

        $request = new Request('GET', 'https://example.com/test', $headers);

        $authenticator = new RequestAuthenticator(new MockKeyLoader($this->keys));
        $authenticator->authenticate($request);
    }

    /**
     * Ensures an exception is thrown if the key cannot be found in the loader.
     *
     * @expectedException \Acquia\Hmac\Exception\KeyNotFoundException
     */
    public function testKeyNotFound()
    {
        $headers = [
            'Content-Type' => 'text/plain',
            'X-Authorization-Timestamp' => time(),
            'Authorization' => 'acquia-http-hmac realm="Pipet service",'
                . 'id="bad-id",'
                . 'nonce="d1954337-5319-4821-8427-115542e08d10",'
                . 'version="2.0",'
                . 'headers="",'
                . 'signature="MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc="',
        ];
        $request = new Request('GET', 'https://example.com/test', $headers);

        $authenticator = new RequestAuthenticator(new MockKeyLoader($this->keys));
        $authenticator->authenticate($request);
    }

    /**
     * Ensures an exception is thrown if the request is missing the X-Authorization-Timestamp header.
     *
     * @expectedException \Acquia\Hmac\Exception\MalformedRequestException
     * @expectedExceptionMessage Request is missing X-Authorization-Timestamp.
     */
    public function testMissingAuthenticationTimestampHeader()
    {
        $headers = [
            'Content-Type' => 'text/plain',
            'Authorization' => 'acquia-http-hmac realm="Pipet service",'
                . 'id="bad-id",'
                . 'nonce="d1954337-5319-4821-8427-115542e08d10",'
                . 'version="2.0",'
                . 'headers="",'
                . 'signature="MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc="',
        ];
        $request = new Request('GET', 'https://example.com/test', $headers);

        $authenticator = new RequestAuthenticator(new MockKeyLoader($this->keys));

        try {
            $authenticator->authenticate($request);
        } catch (MalformedRequestException $e) {
            $this->assertSame($request, $e->getRequest());
            throw $e;
        }
    }
}
