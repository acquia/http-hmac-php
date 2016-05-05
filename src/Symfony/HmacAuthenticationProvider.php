<?php

namespace Acquia\Hmac\Symfony;

use Acquia\Hmac\RequestAuthenticatorInterface;
use Symfony\Bridge\PsrHttpMessage\Factory\DiactorosFactory;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

/**
 * Provides the means to authenticate an HTTP HMAC request.
 */
class HmacAuthenticationProvider implements AuthenticationProviderInterface
{
    /**
     * @var \Acquia\Hmac\RequestAuthenticatorInterface
     *   A HMAC request authenticator service.
     */
    protected $authenticator;

    /**
     * Initializes the authentication provider.
     *
     * @param \Acquia\Hmac\RequestAuthenticatorInterface $authenticator
     *   The HMAC request authenticator service.
     */
    public function __construct(RequestAuthenticatorInterface $authenticator)
    {
        $this->authenticator = $authenticator;
    }

    /**
     * {@inheritDoc}
     */
    public function authenticate(TokenInterface $token)
    {
        $psr7Factory = new DiactorosFactory();
        $psr7Request = $psr7Factory->createRequest($token->getRequest());

        try {
            $key = $this->authenticator->authenticate($psr7Request);

            return new HmacToken($token->getRequest(), $key);
        } catch (\Exception $e) {
            throw new AuthenticationException($e->getMessage());
        }
    }

    /**
     * {@inheritDoc}
     */
    public function supports(TokenInterface $token)
    {
        return $token instanceof HmacToken;
    }
}
