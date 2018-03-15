<?php

namespace Acquia\Hmac\Test\Symfony;

use Acquia\Hmac\KeyInterface;
use Acquia\Hmac\Symfony\HmacToken;
use Symfony\Component\HttpFoundation\Request;
use PHPUnit\Framework\TestCase;

/**
 * Tests the Symfony authentication token.
 */
class HmacTokenTest extends TestCase
{
    /**
     * Ensures the getters work as expected.
     */
    public function testGetters()
    {
        $request = $this->getMock(Request::class);
        $key = $this->getMock(KeyInterface::class);

        $token = new HmacToken($request, $key);

        $this->assertEquals($request, $token->getRequest());
        $this->assertEquals($key, $token->getCredentials());
    }
}
