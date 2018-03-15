<?php

namespace Acquia\Hmac\Test\Symfony;

use Acquia\Hmac\Key;
use Acquia\Hmac\Symfony\HmacResponseListener;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\KernelEvents;
use PHPUnit\Framework\TestCase;

/**
 * Tests the response listener for Symfony-based authentication.
 */
class HmacResponseListenerTest extends TestCase
{
    /**
     * Ensures the response listener listens to the correct events.
     */
    public function testGetSubsribedEvents()
    {
        $this->assertArrayHasKey(KernelEvents::RESPONSE, HmacResponseListener::getSubscribedEvents());
    }

    /**
     * Ensures the response listener only responds to the main request.
     */
    public function testSubRequestsAreIgnored()
    {
        $kernel   = $this->getMock(HttpKernelInterface::class);
        $request  = $this->getMock(Request::class);
        $response = $this->getMock(Response::class);

        $event    = new FilterResponseEvent($kernel, $request, HttpKernelInterface::SUB_REQUEST, $response);
        $listener = new HmacResponseListener();

        $listener->onKernelResponse($event);

        $this->assertSame($response, $event->getResponse());
    }

    /**
     * Ensures the response listener only responds to HMAC-tagged requests.
     */
    public function testNonHmacRequestsAreIgnored()
    {
        $kernel   = $this->getMock(HttpKernelInterface::class);
        $response = $this->getMock(Response::class);

        $request  = new Request();
        $event    = new FilterResponseEvent($kernel, $request, HttpKernelInterface::MASTER_REQUEST, $response);
        $listener = new HmacResponseListener();

        $listener->onKernelResponse($event);

        $this->assertSame($response, $event->getResponse());
    }

    /**
     * Ensures the response listener signs responses correctly.
     */
    public function testHmacResponsesAreSigned()
    {
        $kernel = $this->getMock(HttpKernelInterface::class);

        $authId     = 'efdde334-fe7b-11e4-a322-1697f925ec7b';
        $authSecret = 'W5PeGMxSItNerkNFqQMfYiJvH14WzVJMy54CPoTAYoI=';
        $timestamp  = 1432075982;
        $authHeader = 'acquia-http-hmac realm="Pipet%20service",id="efdde334-fe7b-11e4-a322-1697f925ec7b",nonce="d1954337-5319-4821-8427-115542e08d10",version="2.0",headers="",signature="Ficfxef2w69S/HoCM8THKWiN/gu2TMMz1skYBc5KPjA="';
        $signature  = 'LusIUHmqt9NOALrQ4N4MtXZEFE03MjcDjziK+vVqhvQ=';

        $request = Request::create('http://example.com');
        $request->headers->set('X-Authorization-Timestamp', $timestamp);
        $request->headers->set('Authorization', $authHeader);
        $request->attributes->set('hmac.key', new Key($authId, $authSecret));

        $response = new Response();
        $event    = new FilterResponseEvent($kernel, $request, HttpKernelInterface::MASTER_REQUEST, $response);
        $listener = new HmacResponseListener();

        $listener->onKernelResponse($event);

        $signedResponse = $event->getResponse();

        $this->assertTrue($signedResponse->headers->has('X-Server-Authorization-HMAC-SHA256'));
        $this->assertEquals($signature, $signedResponse->headers->get('X-Server-Authorization-HMAC-SHA256'));
    }
}
