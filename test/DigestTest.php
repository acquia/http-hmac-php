<?php

namespace Acquia\Hmac\Test;

use Acquia\Hmac\RequestSigner;
use Acquia\Hmac\Digest\Digest;
use PHPUnit\Framework\TestCase;

/**
 * Tests the HTTP HMAC digest
 */
class DigestTest extends TestCase
{
    /**
     * @var string
     *   A sample secret key.
     */
    protected $authSecret;

    /**
     * @var string
     *   A sample message.
     */
    protected $message;

    /**
     * {@inheritDoc}
     */
    protected function setUp()
    {
        $this->authSecret = 'TXkgU2VjcmV0IEtleSBUaGF0IGlzIFZlcnkgU2VjdXJl';
        $this->message    = 'The quick brown fox jumps over the lazy dog.';
    }

    /**
     * Ensures a message is signed correctly with a secret key.
     */
    public function testSign()
    {
        $digest = new Digest();

        $hash = 'vcOqnVc4i0YB5ILPTt92mE4zsBHC0cMHq6YpM5Gw8rI=';

        $this->assertEquals($hash, $digest->sign($this->message, $this->authSecret));
    }

    /**
     * Ensures a message is hashed correctly.
     */
    public function testHash()
    {
        $digest = new Digest();

        $hash = '71N/JciVv6eCUmUpqbY9l6pjFWTV14nCt2VEjIY1+2w=';

        $this->assertEquals($hash, $digest->hash($this->message));
    }

    /**
     * Ensures the message does not sign correctly if the secret contains invalid characters.
     */
    public function testSignFailsWithMalformedSecret()
    {
        $digest = new Digest();

        $invalid_secret = $this->authSecret . '%%%';
        $hash = 'vcOqnVc4i0YB5ILPTt92mE4zsBHC0cMHq6YpM5Gw8rI=';

        $this->assertNotEquals($hash, $digest->sign($this->message, $invalid_secret));
    }
}
