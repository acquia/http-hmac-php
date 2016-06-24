<?php

namespace Acquia\Hmac\Symfony;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

/**
 * Response handling for a client making an unauthenticated request.
 */
class HmacAuthenticationEntryPoint implements AuthenticationEntryPointInterface
{
    /**
     * {@inheritDoc}
     */
    public function start(Request $request, AuthenticationException $authException = null)
    {
        $response = new Response();
        $response->setStatusCode(401, $authException ? $authException->getMessage() : null);

        return $response;
    }
}
