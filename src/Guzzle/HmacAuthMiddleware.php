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
        $this->setId($id);
        $this->setSecretKey($secretKey);
    }

    // @TODO 3.0 document
    public function getId()
    {
        return $this->id;
    }

    // @TODO 3.0 document
    public function setId($id)
    {
        $this->id = $id;
    }

    // @TODO 3.0 document
    public function getSecretKey()
    {
        return $this->secretKey;
    }

    // @TODO 3.0 document
    public function setSecretKey($secretKey)
    {
        $this->secretKey = $secretKey;
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
        $this->requestSigner->setDefaultContentType($this->getDefaultContentType());
        return $this->requestSigner->signRequest($request, $this->getId(), $this->getSecretKey());
    }
}
