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
    protected $secretKey;

    /**
     * @param \Acquia\Hmac\RequestSignerInterface $requestSigner
     * @param string $id
     * @param string $secretKey
     */
    public function __construct(RequestSignerInterface $requestSigner, $secretKey)
    {
        $this->requestSigner = $requestSigner;
        $this->setSecretKey($secretKey);
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

    // @TODO 3.0 document
    public function signRequest(RequestInterface $request) {
        return $this->requestSigner->signRequest($request, $this->getSecretKey());
    }
}
