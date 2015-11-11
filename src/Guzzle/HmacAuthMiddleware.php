<?php

namespace Acquia\Hmac\Guzzle;

use Acquia\Hmac\RequestSignerInterface;
use Acquia\Hmac\Request\Guzzle as RequestWrapper;
use Psr\Http\Message\RequestInterface;

class HmacAuthMiddleware
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
     * @var \Psr\Http\Message\RequestInterface|null
     */
    protected $lastRequest;

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
     * Called when the middleware is handled.
     *
     * @param callable $handler
     *
     * @return \Closure
     */
    public function __invoke(callable $handler)
    {
        return function ($request, array $options) use ($handler) {
            $this->lastRequest = $request = $this->signRequest($request);
            return $handler($request, $options);
        };
    }

    /**
     * Signs the request, adds the HMAC hash to the authorization header.
     *
     * @param \Psr\Http\Message\RequestInterface $request
     *
     * @return \Psr\Http\Message\RequestInterface
     */
    public function signRequest(RequestInterface $request)
    {
        if (!$request->hasHeader('Date')) {
            $time = new \DateTime();
            $time->setTimezone(new \DateTimeZone('GMT'));
            $request = $request->withHeader('Date', $time->format('D, d M Y H:i:s \G\M\T'));
        }

        if (!$request->hasHeader('Content-Type')) {
            $request = $request->withHeader('Content-Type', $this->defaultContentType);
        }

        $authorization = $this->requestSigner->getAuthorization(new RequestWrapper($request), $this->id, $this->secretKey);
        $request = $request->withHeader('Authorization', $authorization);

        return $request;
    }

    /**
     * @var \Psr\Http\Message\RequestInterface|null
     */
    public function getLastRequest()
    {
        return $this->lastRequest;
    }
}