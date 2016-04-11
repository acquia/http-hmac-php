<?php

namespace Acquia\Hmac\Guzzle;

use Acquia\Hmac\KeyInterface;
use Acquia\Hmac\RequestSigner;
use Psr\Http\Message\RequestInterface;

class HmacAuthMiddleware
{
    /**
     * @var \Acquia\Hmac\RequestSignerInterface
     */
    protected $requestSigner;

    /**
     * @param \Acquia\Hmac\KeyInterface $key
     * @param string $realm
     */
    public function __construct(KeyInterface $key, $realm = 'Acquia')
    {
        $this->requestSigner = new RequestSigner($key, $realm);
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
     * Signs the request with the appropriate headers.
     *
     * @param \Psr\Http\Message\RequestInterface $request
     *
     * @return \Psr\Http\Message\RequestInterface
     */
    public function signRequest(RequestInterface $request)
    {
        return $this->requestSigner->signRequest($request);
    }
}
