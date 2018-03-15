<?php

namespace Acquia\Hmac\Test;

use Acquia\Hmac\AuthorizationHeaderBuilder;
use Acquia\Hmac\Digest\Digest;
use Acquia\Hmac\Key;
use Acquia\Hmac\RequestAuthenticator;
use Acquia\Hmac\RequestSigner;
use Acquia\Hmac\ResponseSigner;
use Acquia\Hmac\Test\Mocks\MockKeyLoader;
use Acquia\Hmac\Test\Mocks\MockRequestAuthenticator;
use Acquia\Hmac\Test\Mocks\MockRequestSigner;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

class AcquiaSpecTest extends TestCase
{
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
     * Get the shared test fixtures.
     */
    public function specFixtureProvider()
    {
        $fixtures_json = file_get_contents(realpath(__DIR__ . "/acquia_spec_features.json"));
        $fixtures = json_decode($fixtures_json, true);
        return $fixtures['fixtures']['2.0'];
    }

    /**
     * @dataProvider specFixtureProvider
     */
    public function testSpec($input, $expectations)
    {
        $key = new Key($input['id'], $input['secret']);
        $digest = new Digest();

        $headers = [
            'X-Authorization-Timestamp' => $input['timestamp'],
            'Content-Type' => $input['content_type'],
        ];
        foreach ($input['headers'] as $header => $value) {
            $headers[$header] = $value;
        }

        $body = !empty($input['content_body']) ? $input['content_body'] : null;

        $request = new Request($input['method'], $input['url'], $headers, $body);

        $authHeaderBuilder = new AuthorizationHeaderBuilder($request, $key);
        $authHeaderBuilder->setRealm($input['realm']);
        $authHeaderBuilder->setId($input['id']);
        $authHeaderBuilder->setNonce($input['nonce']);
        $authHeaderBuilder->setVersion('2.0');
        $authHeaderBuilder->setCustomHeaders($input['signed_headers']);
        $authHeader = $authHeaderBuilder->getAuthorizationHeader();

        $requestSigner = new MockRequestSigner($key, $input['realm'], $digest, $authHeader);

        $signedRequest = $requestSigner->signRequest($request, $input['signed_headers']);

        $signedAuthHeader = $signedRequest->getHeaderLine('Authorization');

        $this->assertContains('id="' . $input['id'] . '"', $signedAuthHeader);
        $this->assertContains('nonce="' . $input['nonce'] . '"', $signedAuthHeader);
        $this->assertContains('realm="' . rawurlencode($input['realm']) . '"', $signedAuthHeader);
        $this->assertContains('signature="' . $expectations['message_signature'] . '"', $signedAuthHeader);
        $this->assertContains('version="2.0"', $signedAuthHeader);

        // Prove that the digest generates the correct signature.
        $signedMessage = $digest->sign($expectations['signable_message'], $input['secret']);
        $this->assertEquals($expectations['message_signature'], $signedMessage);

        // Prove that the authenticator can authenticate the request.
        $keyLoader = new MockKeyLoader([
                $input['id'] => $input['secret'],
        ] + $this->keys);
        $authenticator = new MockRequestAuthenticator($keyLoader, null, $input['timestamp']);
        $compareKey = $authenticator->authenticate($signedRequest);

        $this->assertEquals($compareKey->getId(), $input['id']);

        // Prove that the response signer generates the correct signature.
        $response = new Response(200, [], $expectations['response_body']);
        $responseSigner = new ResponseSigner($key, $signedRequest);

        $response = $responseSigner->signResponse($response);

        $this->assertTrue($response->hasHeader('X-Server-Authorization-HMAC-SHA256'));
        $this->assertEquals($expectations['response_signature'], $response->getHeaderLine('X-Server-Authorization-HMAC-SHA256'));
    }
}
