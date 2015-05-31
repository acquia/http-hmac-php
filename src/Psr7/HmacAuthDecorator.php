<?php

namespace Acquia\Hmac\Psr7;

use Acquia\Hmac\RequestSignerInterface;
use Acquia\Hmac\Request\Psr7RequestAdapter as RequestWrapper;
use Psr\Http\Message\RequestInterface;

class HmacAuthDecorator
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
        $this->id            = $id;
        $this->secretKey     = $secretKey;
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
     * @param \Psr\Http\Message\RequestInterface $request
     *
     * @return \Psr\Http\Message\RequestInterface $request
     */
    public function __invoke(RequestInterface &$request)
    {
        if (!$request->hasHeader('Date')) {
            $time = new \DateTime();
            $time->setTimezone(new \DateTimeZone('GMT'));
            $request = $request->withHeader('Date', $time->format('D, d M Y H:i:s \G\M\T'));
        }

        if (!$request->hasHeader('Content-Type')) {
            $request = $request->withHeader('Content-Type', $this->defaultContentType);
        }

        $requestWrapper = new requestWrapper($request);

        $authorization = $this->requestSigner->getAuthorization($requestWrapper, $this->id, $this->secretKey);

        $request = $request->withHeader('Authorization', $authorization);

        // Return decorated request
        return $request;
    }
}
