<?php

namespace Acquia\Hmac\Symfony;

use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

/**
 * Handles an authentication event.
 */
class HmacAuthenticationListener
{
    /**
     * @var \Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface
     *   Stores a security token for authentication.
     */
    protected $tokenStorage;

    /**
     * @var \Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface
     *   Manages the available authentication providers.
     */
    protected $authManager;

    /**
     * @var \Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface
     *   Response handling for a client making an unauthenticated request.
     */
    protected $entryPoint;

    /**
     * Initializes the authentication listener.
     *
     * @param \Symfony\Component\Security\Csrf\TokenStorage\TokenStorageInterface $tokenStorage
     *   Storage for a security token during authentication.
     * @param \Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface $authManager
     *   An authentication provider manager.
     * @param \Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface $entryPoint
     *   An entry point for unauthenticated client requests.
     */
    public function __construct(TokenStorageInterface $tokenStorage, AuthenticationManagerInterface $authManager, AuthenticationEntryPointInterface $entryPoint)
    {
        $this->tokenStorage = $tokenStorage;
        $this->authManager = $authManager;
        $this->entryPoint = $entryPoint;
    }

    /**
     * Handles the incoming request.
     *
     * @param \Symfony\Component\HttpKernel\Event\RequestEvent $event
     *   The event corresponding to the request.
     */
    public function __invoke(RequestEvent $event)
    {
        $request = $event->getRequest();

        // Requests require an Authorization header.
        if (!$request->headers->has('Authorization')) {
            $event->setResponse($this->entryPoint->start($request));
            return;
        }

        $token = new HmacToken($request);

        try {
            $authToken = $this->authManager->authenticate($token);
            $this->tokenStorage->setToken($authToken);
            $request->attributes->set('hmac.key', $authToken->getCredentials());
        } catch (AuthenticationException $e) {
            $event->setResponse($this->entryPoint->start($request, $e));
        }
    }
}
