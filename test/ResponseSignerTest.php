<?php

namespace Acquia\Hmac\Test;

use Acquia\Hmac\AuthorizationHeader;
use Acquia\Hmac\AuthorizationHeaderBuilder;
use Acquia\Hmac\Digest\Digest;
use Acquia\Hmac\Key;
use Acquia\Hmac\ResponseSigner;
use Acquia\Hmac\Test\Mocks\MockRequestSigner;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

/**
 * Tests the response signer.
 */
class ResponseSignerTest extends TestCase
{
    /**
     * Ensures the correct headers are added when the response is signed.
     */
    public function testSignResponse()
    {
        $authId = 'efdde334-fe7b-11e4-a322-1697f925ec7b';
        $authSecret = 'W5PeGMxSItNerkNFqQMfYiJvH14WzVJMy54CPoTAYoI=';
        $realm = 'Pipet service';
        $nonce = 'd1954337-5319-4821-8427-115542e08d10';
        $timestamp = 1432075982;
        $signature = 'dAE9Kizn1PCOrc45H/X41RdFMCwpED18k9iJjrHFqUU=';
        $body = 'Test body string';

        $authKey = new Key($authId, $authSecret);

        $headers = [
            'X-Authorization-Timestamp' => $timestamp,
        ];

        $request = new Request('GET', 'http://example.com', $headers);
        $authHeaderBuilder = new AuthorizationHeaderBuilder($request, $authKey);
        $authHeaderBuilder->setRealm($realm);
        $authHeaderBuilder->setId($authKey->getId());
        $authHeaderBuilder->setNonce($nonce);
        $authHeader = $authHeaderBuilder->getAuthorizationHeader();

        $requestSigner = new MockRequestSigner($authKey, $realm, new Digest(), $authHeader);
        $signedRequest = $requestSigner->signRequest($request);

        $response = new Response(200, [], $body);

        $responseSigner = new ResponseSigner($authKey, $signedRequest);
        $signedResponse = $responseSigner->signResponse($response);

        $this->assertTrue($signedResponse->hasHeader('X-Server-Authorization-HMAC-SHA256'));
        $this->assertEquals($signature, $signedResponse->getHeaderLine('X-Server-Authorization-HMAC-SHA256'));
        $this->assertEquals($body, $response->getBody()->getContents());
    }
}
