<?php

namespace Acquia\Hmac\Symfony;

use Acquia\Hmac\ResponseSigner;
use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\ServerRequestFactory;
use Laminas\Diactoros\StreamFactory;
use Laminas\Diactoros\UploadedFileFactory;
use Symfony\Bridge\PsrHttpMessage\Factory\DiactorosFactory;
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
        if (!$event->isMasterRequest()) {
            return;
        }

        $request = $event->getRequest();
        $response = $event->getResponse();

        if ($request->attributes->has('hmac.key')) {
            if (class_exists(DiactorosFactory::class)) {
                $httpMessageFactory = new DiactorosFactory();
            } else {
                $httpMessageFactory = new PsrHttpFactory(new ServerRequestFactory(), new StreamFactory(), new UploadedFileFactory(), new ResponseFactory());
            }

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
