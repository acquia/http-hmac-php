<?php

namespace Acquia\Hmac\Test;

use Acquia\Hmac\AuthorizationHeaderBuilder;
use Acquia\Hmac\Digest\Digest;
use Acquia\Hmac\Key;
use Acquia\Hmac\RequestSigner;
use Acquia\Hmac\Test\Mocks\MockRequestSigner;
use GuzzleHttp\Psr7\Request;
use PHPUnit\Framework\TestCase;

/**
 * Tests the request signer.
 */
class RequestSignerTest extends TestCase
{
    /**
     * @var \Acquia\Hmac\KeyInterface
     *   A sample key.
     */
    protected $authKey;

    /**
     * @var string
     *   A sample realm/provider.
     */
    protected $realm;

    /**
     * @var int
     *   A sample timestamp.
     */
    protected $timestamp;

    /**
     * {@inheritDoc}
     */
    protected function setUp()
    {
        $authId     = 'efdde334-fe7b-11e4-a322-1697f925ec7b';
        $authSecret = 'W5PeGMxSItNerkNFqQMfYiJvH14WzVJMy54CPoTAYoI=';

        $this->authKey   = new Key($authId, $authSecret);
        $this->realm     = 'Pipet service';
        $this->timestamp = 1432075982;
    }

    /**
     * Ensures the correct headers are generated when signing a request.
     */
    public function testSignRequest()
    {
        $headers = [
            'Content-Type' => 'text/plain',
            'X-Authorization-Timestamp' => $this->timestamp,
        ];

        $request = new Request('GET', 'https://example.acquiapipet.net/v1.0/task-status/133?limit=10', $headers);

        $digest = new Digest();

        $authHeaderBuilder = new AuthorizationHeaderBuilder($request, $this->authKey, $digest);
        $authHeaderBuilder->setRealm($this->realm);
        $authHeaderBuilder->setId($this->authKey->getId());
        $authHeaderBuilder->setNonce('d1954337-5319-4821-8427-115542e08d10');
        $authHeader = $authHeaderBuilder->getAuthorizationHeader();

        $signer = new MockRequestSigner($this->authKey, $this->realm, $digest, $authHeader);

        $signedRequest = $signer->signRequest($request);

        $this->assertFalse($signedRequest->hasHeader('X-Authorization-Content-SHA256'));
        $this->assertTrue($signedRequest->hasHeader('X-Authorization-Timestamp'));
        $this->assertEquals($this->timestamp, $signedRequest->getHeaderLine('X-Authorization-Timestamp'));
        $this->assertTrue($signedRequest->hasHeader('Authorization'));
        $this->assertContains('signature="MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc="', $signedRequest->getHeaderLine('Authorization'));

        // Ensure that we can get the AuthorizationHeader back from the request.
        $signedAuthRequest = $signer->getAuthorizedRequest($signedRequest);
        $this->assertContains('signature="MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc="', $signedAuthRequest->getHeaderLine('Authorization'));
    }

    /**
     * Ensures the X-Authorization-Timestamp header is unmodified if already set.
     */
    public function testAuthorizationTimestampExists()
    {
        $signer = new RequestSigner($this->authKey, $this->realm);

        $headers = [
            'X-Authorization-Timestamp' => $this->timestamp,
        ];

        $request = new Request('GET', 'https://example.acquiapipet.net/v1.0/task-status/133?limit=10', $headers);

        $timestampedRequest = $signer->getTimestampedRequest($request);

        $this->assertTrue($timestampedRequest->hasHeader('X-Authorization-Timestamp'));
        $this->assertEquals($this->timestamp, $timestampedRequest->getHeaderLine('X-Authorization-Timestamp'));
    }

    /**
     * Ensures the X-Authorization-Timestamp header is set when a \DateTime is provided.
     */
    public function testAuthorizationTimestampCustomDateTime()
    {
        $signer = new RequestSigner($this->authKey, $this->realm);

        $date = new \DateTime();
        $date->setTimestamp($this->timestamp);

        $request = new Request('GET', 'https://example.acquiapipet.net/v1.0/task-status/133?limit=10');

        $timestampedRequest = $signer->getTimestampedRequest($request, $date);

        $this->assertTrue($timestampedRequest->hasHeader('X-Authorization-Timestamp'));
        $this->assertEquals($this->timestamp, $timestampedRequest->getHeaderLine('X-Authorization-Timestamp'));
    }

    /**
     * Ensures the X-Authorization-Content-SHA256 header is set correctly if there is a request body.
     */
    public function testAuthprizationContentSha256()
    {
        $signer = new RequestSigner($this->authKey, $this->realm);

        $body = '{"method":"hi.bob","params":["5","4","8"]}';
        $hashedBody = '6paRNxUA7WawFxJpRp4cEixDjHq3jfIKX072k9slalo=';

        $request = new Request('GET', 'https://example.acquiapipet.net/v1.0/task-status/133?limit=10', [], $body);

        $contentHashedRequest = $signer->getContentHashedRequest($request);

        $this->assertTrue($contentHashedRequest->hasHeader('X-Authorization-Content-SHA256'));
        $this->assertEquals($hashedBody, $contentHashedRequest->getHeaderLine('X-Authorization-Content-SHA256'));
    }

    /**
     * Ensures the X-Authorization-Content-SHA256 header is not set if there is no request body.
     */
    public function testAuthorizationContentSha256NoBody()
    {
        $signer = new RequestSigner($this->authKey, $this->realm);

        $request = new Request('GET', 'https://example.acquiapipet.net/v1.0/task-status/133?limit=10');

        $contentHashedRequest = $signer->getContentHashedRequest($request);

        $this->assertFalse($contentHashedRequest->hasHeader('X-Authorization-Content-SHA256'));
    }
}
