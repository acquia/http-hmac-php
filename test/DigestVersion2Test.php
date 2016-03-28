<?php

namespace Acquia\Hmac\Test;

use Acquia\Hmac\RequestSigner;
use Acquia\Hmac\Digest\Version2 as Digest;

class DigestVersion2Test extends \PHPUnit_Framework_TestCase
{
    // @TODO 3.0 replace this?
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
        // @TODO 3.0 add custom headers into the message.
        //$signer->addCustomHeader('Custom1');

        $request = new DummyRequest();
        $request->queryParameters = 'limit=20';
        $request->headers = array(
            'Content-Type' => 'text/plain',
            'X-Authorization-Timestamp' => '1432075982',
            'Authorization' => 'acquia-http-hmac realm:"Pipet service",' . "\n"
            . 'id:"' . $this->auth_id . '",' . "\n"
            . 'nonce:"24c0c836-4f6c-4ed6-a6b0-e091d75ea19d",' . "\n"
            . 'version:"2.0",' . "\n"
            . 'headers:"",' . "\n"
            . 'signature:"P9D+Oc8QDU0puyGuqJHvrneek02g0F5D0+2qrXmSOOA"',
        );

        $digest = new Digest();

        $this->assertEquals(self::EXPECTED_HASH, $digest->get($signer, $request, $this->auth_secret));

        // Change the secret key
        $this->assertNotEquals(self::EXPECTED_HASH, $digest->get($signer, $request, 'bad-key'));

        // Test case insensitive method.
        $request->method = 'gEt';
        $this->assertEquals(self::EXPECTED_HASH, $digest->get($signer, $request, $this->auth_secret));

        // Test case insensitive content type.
        $request->headers['Content-Type'] = 'TeXt/PlAiN';
        $this->assertEquals(self::EXPECTED_HASH, $digest->get($signer, $request, $this->auth_secret));

        // Test changing the algorithm
        $digest->setAlgorithm('sha1');
        // @TODO 3.0 why does this not match?
        $this->assertNotEquals(self::EXPECTED_HASH, $digest->get($signer, $request, $this->auth_secret));
    }

    public function testPostMessage()
    {
        $signer = new RequestSigner();
        $digest = new Digest();

        // @TODO 3.0 add custom headers into the message.
        $secretKey = 'W5PeGMxSItNerkNFqQMfYiJvH14WzVJMy54CPoTAYoI=';

        $request = new DummyRequest();
        $request->method = 'POST';
        $request->path = '/v1.0/task';
        $request->queryParameters = '';
        $request->body = '{"method":"hi.bob","params":["5","4","8"]}';
        $request->headers = array(
            'Content-Type' => 'application/json',
            'Content-Length' => strlen($request->body),
            'X-Authorization-Timestamp' => '1432075982',
            'X-Authorization-Content-SHA256' => $signer->getHashedBody($request),
            'Authorization' => 'acquia-http-hmac realm:"Pipet service",' . "\n"
            . 'id:"efdde334-fe7b-11e4-a322-1697f925ec7b",' . "\n"
            . 'nonce:"d1954337-5319-4821-8427-115542e08d10",' . "\n"
            . 'version:"2.0",' . "\n"
            . 'headers:"",' . "\n"
            . 'signature:"XDBaXgWFCY3aAgQvXyGXMbw9Vds2WPKJe2yP+1eXQgM"',
        );

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
        // @TODO 3.0 why does this not match?
        $this->assertNotEquals('XDBaXgWFCY3aAgQvXyGXMbw9Vds2WPKJe2yP+1eXQgM=', $digest->get($signer, $request, $secretKey));

        $signer = new RequestSigner();
        // Slight variation of the POST request.
        $secretKey = 'eox4TsBBPhpi737yMxpdBbr3sgg/DEC4m47VXO0B8qJLsbdMsmN47j/ZF/EFpyUKtAhm0OWXMGaAjRaho7/93Q==';
        $request = new DummyRequest();
        $request->host = '54.154.147.142:3000';
        $request->method = 'POST';
        $request->path = '/register';
        $request->queryParameters = '';
        $request->body = '{"method":"hi.bob","params":["5","4","8"]}';
        $request->headers = array(
            'Content-Type' => 'application/json',
            'Content-Length' => strlen($request->body),
            'X-Authorization-Timestamp' => '1449578521',
            'X-Authorization-Content-SHA256' => $signer->getHashedBody($request),
            'Custom1' => 'value1',
            'Custom2' => 'value2',
            'Authorization' => 'acquia-http-hmac realm:"Plexus",' . "\n"
            . 'id:"f0d16792-cdc9-4585-a5fd-bae3d898d8c5",' . "\n"
            . 'nonce:"64d02132-40bf-4fce-85bf-3f1bb1bfe7dd",' . "\n"
            . 'version:"2.0",' . "\n"
            . 'headers:"Custom1;Custom2",' . "\n"
            . 'signature:"4VtBHjqrdDeYrJySoJVDUHpN9u3vyTsyOLz4chezi98="',
        );

        $digest = new Digest();

        // @TODO 3.0 I'm not 100% about this hash, we don't have any reference implementations using signed headers to match against.
        $this->assertEquals('4VtBHjqrdDeYrJySoJVDUHpN9u3vyTsyOLz4chezi98=', $digest->get($signer, $request, $secretKey));
    }

}
