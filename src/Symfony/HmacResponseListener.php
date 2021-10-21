<?php

namespace Acquia\Hmac\Symfony;

use Acquia\Hmac\ResponseSigner;
use Nyholm\Psr7\Factory\Psr17Factory;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Signs the response from an HTTP HMAC-authenticated request.
 */
class HmacResponseListener implements EventSubscriberInterface
{
    /**
     * @param \Symfony\Component\HttpKernel\Event\ResponseEvent $event
     */
    public function onKernelResponse(ResponseEvent $event)
    {
        $mainRequest = method_exists($event, 'isMainRequest') ? $event->isMainRequest() : $event->isMasterRequest();
        if (!$mainRequest) {
            return;
        }

        $request = $event->getRequest();
        $response = $event->getResponse();

        if ($request->attributes->has('hmac.key')) {
            $psr17Factory = new Psr17Factory();
            $httpMessageFactory = new PsrHttpFactory($psr17Factory, $psr17Factory, $psr17Factory, $psr17Factory);
            $foundationFactory = new HttpFoundationFactory();

            $psr7Request = $httpMessageFactory->createRequest($request);
            $psr7Response = $httpMessageFactory->createResponse($response);

            $signer = new ResponseSigner($request->attributes->get('hmac.key'), $psr7Request);
            $signedResponse = $signer->signResponse($psr7Response);

            $event->setResponse($foundationFactory->createResponse($signedResponse));
        }
    }

    /**
     * {@inheritdoc}
     */
    public static function getSubscribedEvents()
    {
        return [KernelEvents::RESPONSE => 'onKernelResponse'];
    }
}
