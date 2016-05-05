<?php

namespace Acquia\Hmac\Test\Symfony;

use Acquia\Hmac\Symfony\HmacAuthenticationEntryPoint;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

/**
 * Tests the entry point for Symfony-based authentication.
 */
class HmacAuthenticationEntryPointTest extends \PHPUnit_Framework_TestCase
{
    /**
     * Ensures the entry point response is set correctly.
     */
    public function testStart()
    {
        $responseMessage = 'This is a test message.';

        $request = $this->getMock(Request::class);
        $authException = new AuthenticationException($responseMessage);

        $entryPoint = new HmacAuthenticationEntryPoint();

        $response = $entryPoint->start($request, $authException);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertContains($responseMessage, (string) $response);
    }
}
