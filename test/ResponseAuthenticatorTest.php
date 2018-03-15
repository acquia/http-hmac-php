<?php

namespace Acquia\Hmac\Test;

use Acquia\Hmac\AuthorizationHeaderBuilder;
use Acquia\Hmac\Digest\Digest;
use Acquia\Hmac\Exception\MalformedResponseException;
use Acquia\Hmac\Key;
use Acquia\Hmac\ResponseAuthenticator;
use Acquia\Hmac\Test\Mocks\MockRequestSigner;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

/**
 * Tests the response authenticator.
 */
class ResponseAuthenticatorTest extends TestCase
{
    /**
     * @var \Acquia\Hmac\KeyInterface
     *   A sample key.
     */
    protected $authKey;

    /**
     * {@inheritDoc}
     */
    protected function setUp()
    {
        $authId     = 'efdde334-fe7b-11e4-a322-1697f925ec7b';
        $authSecret = 'W5PeGMxSItNerkNFqQMfYiJvH14WzVJMy54CPoTAYoI=';

        $this->authKey   = new Key($authId, $authSecret);
    }

    /**
     * Ensures a response can be authenticated.
     */
    public function testIsAuthentic()
    {
        $realm = 'Pipet service';
        $nonce = 'd1954337-5319-4821-8427-115542e08d10';
        $timestamp = 1432075982;
        $signature = 'LusIUHmqt9NOALrQ4N4MtXZEFE03MjcDjziK+vVqhvQ=';

        $requestHeaders = [
            'X-Authorization-Timestamp' => $timestamp,
        ];

        $request = new Request('GET', 'http://example.com', $requestHeaders);
        $authHeaderBuilder = new AuthorizationHeaderBuilder($request, $this->authKey);
        $authHeaderBuilder->setRealm($realm);
        $authHeaderBuilder->setId($this->authKey->getId());
        $authHeaderBuilder->setNonce($nonce);
        $authHeader = $authHeaderBuilder->getAuthorizationHeader();

        $requestSigner = new MockRequestSigner($this->authKey, $realm, new Digest(), $authHeader);
        $signedRequest = $requestSigner->signRequest($request);

        $responseHeaders = [
            'X-Server-Authorization-HMAC-SHA256' => $signature,
        ];

        $response = new Response(200, $responseHeaders);

        $authenticator = new ResponseAuthenticator($signedRequest, $this->authKey);

        $this->assertTrue($authenticator->isAuthentic($response));
    }

    /**
     * Ensures an exception is thrown if response is missing a X-Server-Authorization-HMAC-SHA256 header.
     *
     * @expectedException \Acquia\Hmac\Exception\MalformedResponseException
     * @expectedExceptionMessage Response is missing required X-Server-Authorization-HMAC-SHA256 header.
     */
    public function testMissingServerAuthorizationHeader()
    {
        $request = new Request('GET', 'http://example.com');
        $response = new Response();

        $authenticator = new ResponseAuthenticator($request, $this->authKey);

        try {
            $authenticator->isAuthentic($response);
        } catch (MalformedResponseException $e) {
            $this->assertSame($response, $e->getResponse());
            throw $e;
        }
    }
}
