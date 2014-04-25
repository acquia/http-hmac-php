<?php

namespace Acquia\Hmac;

class RequestSigner implements RequestSignerInterface
{
    /**
     * @var \Acquia\Hmac\Digest\DigestInterface
     */
    protected $digest;

    /**
     * @var string
     */
    protected $provider = 'Acquia';

    /**
     * @var array
     */
    protected $timestampHeaders = array('Date');

    /**
     * @var array
     */
    protected $customHeaders = array();

    /**
     * @param \Acquia\Hmac\Digest\DigestInterface $digest
     */
    public function __construct(Digest\DigestInterface $digest = null)
    {
        $this->digest = $digest ?: new Digest\Version1();
    }

    /**
     * {@inheritDoc}
     *
     * @throws \Acquia\Hmac\Exception\MalformedRequest
     */
    public function getSignature(Request\RequestInterface $request)
    {
        if (!$request->hasHeader('Authorization')) {
            throw new Exception\MalformedRequestException('Authorization header required');
        }

        $provider = preg_quote($this->provider, '@');
        $pattern = '@^' . $provider . ' ([a-zA-Z0-9]+):([a-zA-Z0-9+/]+={0,2})$@';

        if (!preg_match($pattern, $request->getHeader('Authorization'), $matches)) {
            throw new Exception\MalformedRequestException('Authorization header not valid');
        }

        $time = $this->getTimestamp($request);
        $timestamp = strtotime($time);
        if (!$timestamp) {
            throw new Exception\MalformedRequestException('Timestamp not valid');
        }

        return new Signature($matches[1], $matches[2], $timestamp);
    }

    /**
     * {@inheritDoc}
     *
     * @throws \InvalidArgumentException
     * @throws \Acquia\Hmac\Exception\InvalidRequestException
     */
    public function signRequest(Request\RequestInterface $request, $secretKey)
    {
        return $this->digest->get($request, $secretKey, $this->timestampHeaders, $this->customHeaders);
    }

    /**
     * {@inheritDoc}
     *
     * @throws \Acquia\Hmac\Exception\InvalidRequestException
     */
    public function getAuthorization(Request\RequestInterface $request, $id, $secretKey, $algorithm = null)
    {
        $signature = $this->signRequest($request, $secretKey, $algorithm);
        return $this->provider . ' ' . $id . ':' . $signature;
    }

    /**
     * @param string $provider
     *
     * @return \Acquia\Hmac\RequestSigner
     */
    public function setProvider($provider)
    {
        $this->provider = $provider;
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function getProvider()
    {
        return $this->provider;
    }

    /**
     * Appends a timestap header to the stack.
     *
     * @param string $header
     *
     * @return \Acquia\Hmac\RequestSigner
     */
    public function addTimestampHeader($header)
    {
        $this->timestampHeaders[] = $header;
        return $this;
    }

    /**
     * @param array $headers
     *
     * @return \Acquia\Hmac\RequestSigner
     */
    public function setTimestampHeaders(array $headers)
    {
        $this->timestampHeaders = $headers;
        return $this;
    }

    /**
     * @return array
     */
    public function getTimestampHeaders()
    {
        return $this->timestampHeaders;
    }

    /**
     * Append a custom headers to be used in the signature.
     *
     * @param string $header
     *
     * @return \Acquia\Hmac\RequestSigner
     */
    public function addCustomHeader($header)
    {
        $this->customHeaders[] = $header;
        return $this;
    }

    /**
     * @param array $headers
     *
     * @return \Acquia\Hmac\RequestSigner
     */
    public function setCustomHeaders(array $headers)
    {
        $this->customHeaders = $headers;
        return $this;
    }

    /**
     * @return array
     */
    public function getCustomHeaders()
    {
        return $this->customHeaders;
    }
}
