<?php

namespace Acquia\Hmac\Test\Symfony;

use Acquia\Hmac\Key;
use Acquia\Hmac\KeyInterface;
use Acquia\Hmac\Symfony\HmacAuthenticationListener;
use Acquia\Hmac\Symfony\HmacToken;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use PHPUnit\Framework\TestCase;

/**
 * Tests the authentication listener for Symfony-based authentication.
 */
class HmacAuthenticationListenerTest extends TestCase
{
    /**
     * Ensures a request fails to authenticate without an Authorization header.
     */
    public function testRequiredAuthorizationHeader()
    {
        $kernel = $this->createMock(HttpKernelInterface::class);
        $storage = $this->createMock(TokenStorageInterface::class);
        $manager = $this->createMock(AuthenticationManagerInterface::class);
        $entry = $this->createMock(AuthenticationEntryPointInterface::class, ['start']);

        $entryResponse = new Response('Authentication failed', 401);
        $entry->expects($this->any())
            ->method('start')
            ->will($this->returnValue($entryResponse));

        $request  = new Request();
        $event    = new RequestEvent($kernel, $request, HttpKernelInterface::MASTER_REQUEST);
        $listener = new HmacAuthenticationListener($storage, $manager, $entry);

        $listener($event);

        $this->assertTrue($event->hasResponse());
        $this->assertEquals($entryResponse->getStatusCode(), $event->getResponse()->getStatusCode());
        $this->assertEquals($entryResponse->getContent(), $event->getResponse()->getContent());
    }

    /**
     * Ensures a request receives the auth key if authenticated properly.
     */
    public function testAuthentication()
    {
        $authId = 'efdde334-fe7b-11e4-a322-1697f925ec7b';
        $authSecret = 'W5PeGMxSItNerkNFqQMfYiJvH14WzVJMy54CPoTAYoI=';

        $kernel  = $this->createMock(HttpKernelInterface::class);
        $storage = $this->createMock(TokenStorageInterface::class);
        $manager = $this->createMock(AuthenticationManagerInterface::class);
        $entry  = $this->createMock(AuthenticationEntryPointInterface::class);

        $request   = new Request();
        $response  = new Response();
        $authKey   = new Key($authId, $authSecret);
        $authToken = new HmacToken($request, $authKey);

        $request->headers->set('Authorization', 'foo');

        $manager->expects($this->any())
            ->method('authenticate')
            ->will($this->returnValue($authToken));

        $event    = new RequestEvent($kernel, $request, HttpKernelInterface::MASTER_REQUEST);
        $listener = new HmacAuthenticationListener($storage, $manager, $entry);

        $event->setResponse($response);
        $listener($event);

        $handledRequest = $event->getRequest();

        $this->assertTrue($handledRequest->attributes->has('hmac.key'));

        $key = $handledRequest->attributes->get('hmac.key');

        $this->assertInstanceOf(KeyInterface::class, $key);
        $this->assertEquals($authId, $key->getId());
        $this->assertEquals($authSecret, $key->getSecret());
    }

    /**
     * Ensures the response is correct if the request fails to authenticate.
     */
    public function testFailedAuthentication()
    {
        $kernel  = $this->createMock(HttpKernelInterface::class);
        $storage = $this->createMock(TokenStorageInterface::class);
        $manager = $this->createMock(AuthenticationManagerInterface::class);
        $entry   = $this->createMock(AuthenticationEntryPointInterface::class);

        $request       = new Request();
        $entryResponse = new Response('Authentication failed', 401);

        $request->headers->set('Authorization', 'foo');

        $manager->expects($this->any())
            ->method('authenticate')
            ->will($this->throwException(new AuthenticationException('Authentication failed')));

        $entry->expects($this->any())
            ->method('start')
            ->will($this->returnValue($entryResponse));

        $event    = new RequestEvent($kernel, $request, HttpKernelInterface::MASTER_REQUEST);
        $listener = new HmacAuthenticationListener($storage, $manager, $entry);

        $listener($event);

        $this->assertTrue($event->hasResponse());
        $this->assertEquals($entryResponse->getStatusCode(), $event->getResponse()->getStatusCode());
        $this->assertEquals($entryResponse->getContent(), $event->getResponse()->getContent());
    }
}
