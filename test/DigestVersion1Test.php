<?php

namespace Acquia\Hmac\Test;

use Acquia\Hmac\RequestSigner;
use Acquia\Hmac\Digest\Version1 as Digest;

class DigestVersion1Test extends \PHPUnit_Framework_TestCase
{
    const EXPECTED_HASH = '0Qub9svYlxjAr8OO7N0/3u0sohs=';

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
        $this->assertEquals('sha1', $digest->getAlgorithm());
    }

    public function testGetMessage()
    {
        $signer = new RequestSigner();
        $signer->addCustomHeader('Custom1');

        $request = new DummyRequest();
        $request->headers = array(
            'Content-Type' => 'text/plain',
            'Date' => 'Fri, 19 Mar 1982 00:00:04 GMT',
            'Custom1' => 'Value1',
        );

        $digest = new Digest();

        $this->assertEquals(self::EXPECTED_HASH, $digest->get($signer, $request, 'secret-key'));

        // Change the secret key
        $this->assertNotEquals(self::EXPECTED_HASH, $digest->get($signer, $request, 'bad-key'));

        // Test case insensitive method.
        $request->method = 'gEt';
        $this->assertEquals(self::EXPECTED_HASH, $digest->get($signer, $request, 'secret-key'));

        // Test case insensitive content type.
        $request->headers['Content-Type'] = 'TeXt/PlAiN';
        $this->assertEquals(self::EXPECTED_HASH, $digest->get($signer, $request, 'secret-key'));

        // Test changing the algorithm
        $digest->setAlgorithm('sha256');
        $this->assertNotEquals(self::EXPECTED_HASH, $digest->get($signer, $request, 'secret-key'));
    }
}
