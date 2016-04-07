<?php

namespace Acquia\Hmac\Guzzle;

use Acquia\Hmac\RequestSignerInterface;
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
            $request = $this->signRequest($request);
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
        // @TODO 3.0 has "X-Authorization-Timestamp" in unix timestamp format.
        if (!$request->hasHeader('X-Authorization-Timestamp')) {
            $time = new \DateTime();
            $time->setTimezone(new \DateTimeZone('GMT'));
            $request = $request->withHeader('X-Authorization-Timestamp', $time->getTimestamp());
        }
        
        if (!$request->hasHeader('Content-Type')) {
            $request = $request->withHeader('Content-Type', $this->defaultContentType);
        }

        if (!$request->hasHeader('X-Authorization-Content-SHA256')) {
            $hashed_body = $this->requestSigner->getHashedBody($request);
            if (!empty($hashed_body)) {
                $request = $request->withHeader('X-Authorization-Content-SHA256', $hashed_body);
            }
        }

        $authorization = $this->requestSigner->getAuthorization($request, $this->id, $this->secretKey, null);
        $signed_request = $request->withHeader('Authorization', $authorization);
        return $signed_request;
    }
}
