<?php

/**
 * A middleware handler to sign all requests.
 */
namespace Acquia\Hmac\Guzzle6;

use Acquia\Hmac\RequestSignerInterface;
use Acquia\Hmac\Request\Guzzle6 as RequestWrapper;
use GuzzleHttp\Handler\CurlHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use Psr\Http\Message\RequestInterface;

class HmacAuthHandler
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
     * @param string                              $id
     * @param string                              $secretKey
     */
    public function __construct(RequestSignerInterface $requestSigner, $id, $secretKey)
    {
        $this->requestSigner = $requestSigner;
        $this->id = $id;
        $this->secretKey = $secretKey;
    }

    /**
     * Creates a new HmacAuthHandler that uses the default handler stack list of
     * middleware.
     */
    public static function createWithMiddleware(RequestSignerInterface $requestSigner, $id, $secretKey, $handler = null)
    {
        $auth_handler = new self($requestSigner, $id, $secretKey);
        $handler = is_callable($handler) ? $handler : new CurlHandler();
        $stack = new HandlerStack();
        $stack->setHandler($handler);
        $stack->push(Middleware::mapRequest(array($auth_handler, 'signRequest')));

        return $stack;
    }

    /**
     * @var string
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
     * @param \Guzzle\Http\Message\RequestInterface
     */
    public function signRequest(RequestInterface $request, array $options = array())
    {
        if (!$request->hasHeader('Date')) {
            $time = new \DateTime();
            $time->setTimezone(new \DateTimeZone('GMT'));
            $request = $request->withAddedHeader('Date', $time->format('D, d M Y H:i:s \G\M\T'));
        }

        if (!$request->hasHeader('Content-Type')) {
            $request = $request->withAddedHeader('Content-Type', $this->defaultContentType);
        }

        $requestWrapper = new RequestWrapper($request);
        $authorization = $this->requestSigner->getAuthorization($requestWrapper, $this->id, $this->secretKey);

        return $request->withAddedHeader('Authorization', $authorization);
    }
}
