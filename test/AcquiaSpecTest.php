<?php

namespace Acquia\Hmac\Test;

use Acquia\Hmac\RequestAuthenticator;
use Acquia\Hmac\RequestSigner;
use Acquia\Hmac\Digest\Version2 as Digest;
use GuzzleHttp\Psr7\Request;

class AcquiaSpecTest extends \PHPUnit_Framework_TestCase
{

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
        $digest = new Digest();

        $headers = [];

        $signer = new RequestSigner();
        $signer->getAuthorizationHeader()->setId($input['id']);
        $signer->getAuthorizationHeader()->setRealm($input['realm']);
        $signer->getAuthorizationHeader()->setNonce($input['nonce']);
        $signer->setTimestamp($input['timestamp']);
        $signer->setDefaultContentType($input['content_type']);

        foreach ($input['headers'] as $key => $value) {
            $headers[$key] = $value;
        }

        foreach ($input['signed_headers'] as $key) {
            $signer->getAuthorizationHeader()->addSignedHeader($key);
        }

        $body = !empty($input['content_body']) ? $input['content_body'] : null;
        $request = new Request($input['method'], $input['url'], $headers, $body);

        // Generate the Authorization header.
        $auth_header = $signer->getAuthorization(
            $request,
            $input['id'],
            $input['secret'],
            $input['nonce']
        );
        $request = $request->withHeader('Authorization', $auth_header);
        $signed_request = $signer->signRequest($request, $input['secret']);
        $signature = $signer->getSignature($signed_request);

        // Prove that the signature is valid.
        $this->assertEquals($expectations['message_signature'], (string) $signature);

        // Prove that the Authorization headers have all expected values.
        $signed_auth_header = $signed_request->getHeaderLine('Authorization');
        $this->assertContains('id="' . $input['id'] . '"', $signed_auth_header);
        $this->assertContains('nonce="' . $input['nonce'] . '"', $signed_auth_header);
        $this->assertContains('realm="' . rawurlencode($input['realm']) . '"', $signed_auth_header);
        $this->assertContains('signature="' . $signature . '"', $signed_auth_header);
        $this->assertContains('version="2.0"', $signed_auth_header);

        // Prove that the signer generates the correct signature.
        $request_signature = $signer->getSignature($signed_request);
        $this->assertEquals($expectations['message_signature'], $request_signature->getSignature());

        // Prove that the digest generates the correct signature.
        $digest_message = $digest->getMessage($signer, $signed_request, $input['secret']);
        $this->assertEquals($expectations['signable_message'], $digest_message);
        $digest_signature = $digest->get($signer, $signed_request, $input['secret']);
        $this->assertEquals($expectations['message_signature'], $digest_signature);

        // Prove that the authenticator can authenticate the request.
        $signer = new RequestSigner();
        $signer->setTimestamp($input['timestamp']);
        $key_loader = new DummyKeyLoader();
        $key_loader->addKey($input['id'], $input['secret']);
        $authenticator = new RequestAuthenticator($signer, time() + 10);
        $key = $authenticator->authenticate($signed_request, $key_loader);
        $this->assertEquals($key->getId(), $input['id']);
    }
}
