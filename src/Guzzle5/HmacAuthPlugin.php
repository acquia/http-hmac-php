<?php

namespace Acquia\Hmac\Guzzle5;

use Acquia\Hmac\RequestSignerInterface;
use Acquia\Hmac\Request\Guzzle5 as RequestWrapper;
use GuzzleHttp\Message\Request;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Event\SubscriberInterface;
use GuzzleHttp\Event\BeforeEvent;


class HmacAuthPlugin implements SubscriberInterface
{
    /**
     * @var \Acquia\Hmac\RequestSignerInterface
     */
    protected $requestSigner;

    /**
     * @var string
     */
    protected $id;

    /**
     * @var string
     */
    protected $secretKey;

    /**
     * @var string
     */
    protected $defaultContentType = 'application/json; charset=utf-8';

    /**
     * @param \Acquia\Hmac\RequestSignerInterface $requestSigner
     * @param string $id
     * @param string $secretKey
     */
    public function __construct(RequestSignerInterface $requestSigner, $id, $secretKey)
    {
        $this->requestSigner = $requestSigner;
        $this->id            = $id;
        $this->secretKey     = $secretKey;
    }

    /**
     * @var string $contentType
     */
    public function setDefaultContentType($contentType)
    {
        $this->defaultContentType = $contentType;
    }

    /**
     * @return string
     */
    public function getDefaultContentType()
    {
        return $this->defaultContentType;
    }

    /**
     * {@inheritdoc}
     */
    public static function getEvents()
    {
        return ['before' => ['onBefore', -1000]];
    }

    /**
     * Request before event handler.
     * 
     * @param \GuzzleHttp\Event\BeforeEvent $event
     */
    public function onBefore(BeforeEvent $event)
    {
        $this->signRequest($event->getRequest());
    }

    /**
     * @param \GuzzleHttp\Message\Request $request
     */
    public function signRequest(Request $request)
    {
        $requestWrapper = new RequestWrapper($request);

        if (!$request->hasHeader('Date')) {
            $time = new \DateTime();
            $time->setTimezone(new \DateTimeZone('GMT'));
            $request->setHeader('Date', $time->format(ClientInterface::HTTP_DATE));
        }

        if (!$request->hasHeader('Content-Type')) {
            $request->setHeader('Content-Type', $this->defaultContentType);
        }

        $authorization = $this->requestSigner->getAuthorization($requestWrapper, $this->id, $this->secretKey);
        $request->setHeader('Authorization', $authorization);
    }
} 