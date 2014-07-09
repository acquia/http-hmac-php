<?php

namespace Acquia\Hmac\Test;

use Acquia\Hmac\Signature;

class SignatureTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @param null|int $timestamp
     *
     * @return \Acquia\Hmac\Signature
     */
    public function getSignature($timestamp = null)
    {
        $timestamp = $timestamp ?: time();
        return new Signature('1', 'test-signature', $timestamp);
    }

    public function testGetId()
    {
        $signature = $this->getSignature();
        $this->assertEquals('1', $signature->getId());
    }

    public function testGetSignature()
    {
        $signature = $this->getSignature();
        $this->assertEquals('test-signature', $signature->getSignature());
    }

    public function testToString()
    {
        $signature = $this->getSignature();
        $this->assertEquals('test-signature', (string) $signature);
    }

    public function testGetTimestamp()
    {
        $signature = $this->getSignature(385344004);
        $this->assertEquals(385344004, $signature->getTimestamp());
    }

    public function testSignatureMatches()
    {
        $signature = $this->getSignature(385344004);
        $this->assertTrue($signature->matches('test-signature'));
    }

    public function testSignatureDoesNotMatch()
    {
        $signature = $this->getSignature(385344004);
        $this->assertFalse($signature->matches('no-match'));
    }

    /**
     * @expectedException \InvalidArgumentException
     */
    public function testInvalidExpiry()
    {
        $signature = $this->getSignature();
        $signature->compareTimestamp('a-bad-expiry');
    }

    public function testNoExpiry()
    {
        $signature = $this->getSignature(385344004);
        $this->assertEquals(0, $signature->compareTimestamp(0));
    }

    public function testExpiredRequest()
    {
        // Threshold of 10 minutes, request 11 minutes old.
        $signature = $this->getSignature(strtotime('-11 minutes'));
        $this->assertEquals(-1, $signature->compareTimestamp('10 minutes'));
    }

    public function testFutureRequest()
    {
        // Threshold of 10 minutes, request 11 minutes in the future.
        $signature = $this->getSignature(strtotime('+11 minutes'));
        $this->assertEquals(1, $signature->compareTimestamp('10 minutes'));
    }

    public function testRequestWithinThreshold()
    {
        // Threshold of 10 minutes, request is current.
        $signature = $this->getSignature();
        $this->assertEquals(0, $signature->compareTimestamp('10 minutes'));
    }
}
