<?php

namespace Acquia\Hmac\Guzzle3;

use Acquia\Hmac\RequestSignerInterface;
use Acquia\Hmac\Request\Guzzle3 as RequestWrapper;
use Guzzle\Common\Event;
use Guzzle\Http\Message\Request;
use Guzzle\Http\ClientInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

class HmacAuthPlugin implements EventSubscriberInterface
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
    public static function getSubscribedEvents()
    {
        return array(
            'request.before_send' => array('onRequestBeforeSend', -1000)
        );
    }

    /**
     * Request before-send event handler.
     *
     * @param \Guzzle\Common\Event $event
     */
    public function onRequestBeforeSend(Event $event)
    {
        $this->signRequest($event['request']);
    }

    /**
     * @param \Guzzle\Http\Message\Request $request
     */
    public function signRequest(Request $request)
    {
        $requestWrapper = new RequestWrapper($request);

        if (!$request->hasHeader('Date')) {
            $time = new \DateTime();
            $request->setHeader('Date', ClientInterface::HTTP_DATE);
        }

        if (!$request->hasHeader('Content-Type')) {
            $request->setHeader('Content-Type', $this->defaultContentType);
        }

        $authorization = $this->requestSigner->getAuthorization($requestWrapper, $this->id, $this->secretKey);
        $request->setHeader('Authorization', $authorization);
    }
}
