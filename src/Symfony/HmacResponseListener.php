<?php

namespace Acquia\Hmac\Symfony;

use Acquia\Hmac\ResponseSigner;
use Symfony\Bridge\PsrHttpMessage\Factory\DiactorosFactory;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Signs the response from an HTTP HMAC-authenticated request.
 */
class HmacResponseListener implements EventSubscriberInterface
{
    /**
     * @param FilterResponseEvent $event
     */
    public function onKernelResponse(FilterResponseEvent $event)
    {
        if (!$event->isMasterRequest()) {
            return;
        }

        $request = $event->getRequest();
        $response = $event->getResponse();

        if ($request->attributes->has('hmac.key')) {
            $psr7Factory = new DiactorosFactory();
            $foundationFactory = new HttpFoundationFactory();

            $psr7Request = $psr7Factory->createRequest($request);
            $psr7Response = $psr7Factory->createResponse($response);

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
