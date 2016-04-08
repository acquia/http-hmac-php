<?php

namespace Acquia\Hmac\Test;

use Acquia\Hmac\RequestSigner;
use Acquia\Hmac\Digest\Version2 as Digest;

class DigestVersion2Test extends \PHPUnit_Framework_TestCase
{
    const EXPECTED_HASH = 'P9D+Oc8QDU0puyGuqJHvrneek02g0F5D0+2qrXmSOOA=';

    protected $auth_id;

    protected $auth_secret;

    protected function setUp()
    {
        $this->auth_id = '615d6517-1cea-4aa3-b48e-96d83c16c4dd';
        $this->auth_secret = 'TXkgU2VjcmV0IEtleSBUaGF0IGlzIFZlcnkgU2VjdXJl';
    }

    public function testSetAlgorithm()
    {
        $digest = new Digest();
        $digest->setAlgorithm('some-algorithm');
        $this->assertEquals('some-algorithm', $digest->getAlgorithm());
    }

    public function testSetAlgorithmInConstructor()
    {
        $digest = new Digest('some-algorithm');
        $this->assertEquals('some-algorithm', $digest->getAlgorithm());
    }

    public function testGetDefaultAlgorithm()
    {
        $digest = new Digest();
        $this->assertEquals('sha256', $digest->getAlgorithm());
    }

    public function testGetMessage()
    {
        $signer = new RequestSigner();
        $signer->setTimestamp(1432075982);

        $headers = array(
            'Content-Type' => 'text/plain',
            'X-Authorization-Timestamp' => '1432075982',
            'Authorization' => 'acquia-http-hmac realm="Pipet%20service",'
            . 'id="' . $this->auth_id . '",'
            . 'nonce="24c0c836-4f6c-4ed6-a6b0-e091d75ea19d",'
            . 'version="2.0",'
            . 'headers="",'
            . 'signature="P9D+Oc8QDU0puyGuqJHvrneek02g0F5D0+2qrXmSOOA"',
        );
        $request = DummyRequest::generate('GET', 'https://example.acquiapipet.net', '/v1.0/task-status/133', 'limit=20', $headers);

        $digest = new Digest();

        $signer->getAuthorizationHeader()->parseAuthorizationHeader($headers['Authorization']);
        $this->assertEquals(self::EXPECTED_HASH, $digest->get($signer, $request, $this->auth_secret));

        // Change the secret key
        $this->assertNotEquals(self::EXPECTED_HASH, $digest->get($signer, $request, 'bad-key'));

        // Test case insensitive method.
        $request->method = 'gEt';
        $this->assertEquals(self::EXPECTED_HASH, $digest->get($signer, $request, $this->auth_secret));

        // Test case insensitive content type.
        $request->headers['Content-Type'] = 'TeXt/PlAiN';
        $this->assertEquals(self::EXPECTED_HASH, $digest->get($signer, $request, $this->auth_secret));
    }

    public function testPostMessage()
    {
        $signer = new RequestSigner();
        $signer->setTimestamp(1432075982);
        $digest = new Digest();

        $secretKey = 'W5PeGMxSItNerkNFqQMfYiJvH14WzVJMy54CPoTAYoI=';

        $method = 'POST';
        $path = '/v1.0/task';
        $body = '{"method":"hi.bob","params":["5","4","8"]}';
        $headers = array(
            'Content-Type' => 'application/json',
            'Content-Length' => strlen($body),
            'X-Authorization-Timestamp' => '1432075982',
            'Authorization' => 'acquia-http-hmac realm="Pipet%20service",'
            . 'id="efdde334-fe7b-11e4-a322-1697f925ec7b",'
            . 'nonce="d1954337-5319-4821-8427-115542e08d10",'
            . 'version="2.0",'
            . 'headers="",'
            . 'signature="XDBaXgWFCY3aAgQvXyGXMbw9Vds2WPKJe2yP+1eXQgM"',
        );
        $request = DummyRequest::generate($method, 'https://example.acquiapipet.net', $path, '', $headers, $body);
        $request = $request->withHeader('X-Authorization-Content-SHA256', $signer->getHashedBody($request));
        $signer->getAuthorizationHeader()->parseAuthorizationHeader($headers['Authorization']);

        $this->assertEquals('XDBaXgWFCY3aAgQvXyGXMbw9Vds2WPKJe2yP+1eXQgM=', $digest->get($signer, $request, $secretKey));

        // Change the secret key
        $this->assertNotEquals('XDBaXgWFCY3aAgQvXyGXMbw9Vds2WPKJe2yP+1eXQgM=', $digest->get($signer, $request, 'bad-key'));

        // Test case insensitive method.
        $request->method = 'pOsT';
        $this->assertEquals('XDBaXgWFCY3aAgQvXyGXMbw9Vds2WPKJe2yP+1eXQgM=', $digest->get($signer, $request, $secretKey));

        // Test case insensitive content type.
        $request->headers['Content-Type'] = 'ApPlicaTion/Json';
        $this->assertEquals('XDBaXgWFCY3aAgQvXyGXMbw9Vds2WPKJe2yP+1eXQgM=', $digest->get($signer, $request, $secretKey));

        // Test changing the algorithm
        $digest->setAlgorithm('sha1');
        $this->assertNotEquals('XDBaXgWFCY3aAgQvXyGXMbw9Vds2WPKJe2yP+1eXQgM=', $digest->get($signer, $request, $secretKey));

        $signer = new RequestSigner();
        $signer->setTimestamp(1449578521);
        // Slight variation of the POST request.
        $secretKey = 'eox4TsBBPhpi737yMxpdBbr3sgg/DEC4m47VXO0B8qJLsbdMsmN47j/ZF/EFpyUKtAhm0OWXMGaAjRaho7/93Q==';
        $host = 'http://54.154.147.142:3000';
        $method = 'POST';
        $path = '/register';
        $body = '{"method":"hi.bob","params":["5","4","8"]}';
        $headers = array(
            'Content-Type' => 'application/json',
            'Content-Length' => strlen($body),
            'X-Authorization-Timestamp' => '1449578521',
            'Custom1' => 'value1',
            'Custom2' => 'value2',
            'Authorization' => 'acquia-http-hmac realm="Plexus",'
            . 'id="f0d16792-cdc9-4585-a5fd-bae3d898d8c5",'
            . 'nonce="64d02132-40bf-4fce-85bf-3f1bb1bfe7dd",'
            . 'version="2.0",'
            . 'headers="Custom1;Custom2",'
            . 'signature="ko7P82BXY98fFVuCStnB+xo7zxJGqMC9rTW0EpDz+do="',
        );
        $request = DummyRequest::generate($method, $host, $path, '', $headers, $body);
        $request = $request->withHeader('X-Authorization-Content-SHA256', $signer->getHashedBody($request));

        $digest = new Digest();
        $signer->getAuthorizationHeader()->parseAuthorizationHeader($headers['Authorization']);
        $this->assertEquals('ko7P82BXY98fFVuCStnB+xo7zxJGqMC9rTW0EpDz+do=', $digest->get($signer, $request, $secretKey));
    }
}
