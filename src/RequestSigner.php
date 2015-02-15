<?php

namespace Acquia\Hmac;

use Acquia\Hmac\Request\RequestInterface;

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
    public function getSignature(RequestInterface $request)
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
    public function signRequest(RequestInterface $request, $secretKey)
    {
        return $this->digest->get($this, $request, $secretKey);
    }

    /**
     * {@inheritDoc}
     *
     * @throws \Acquia\Hmac\Exception\InvalidRequestException
     */
    public function getAuthorization(RequestInterface $request, $id, $secretKey)
    {
        $signature = $this->signRequest($request, $secretKey);
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
     * {@inheritDoc}
     */
    public function getContentType(RequestInterface $request)
    {
        if (!$request->hasHeader('Content-Type')) {
            throw new Exception\MalformedRequestException('Content type header required');
        }

        return $request->getHeader('Content-Type');
    }

    /**
     * {@inheritDoc}
     */
    public function getTimestamp(RequestInterface $request)
    {
        foreach ($this->timestampHeaders as $header) {
            if ($request->hasHeader($header)) {
                return $request->getHeader($header);
            }
        }

        if (count($this->timestampHeaders) > 1) {
            $message = 'At least one of the following headers is required: ' . join(', ', $this->timestampHeaders);
        } else {
            $message = $this->timestampHeaders[0] . ' header required';
        }

        throw new Exception\MalformedRequestException($message);
    }

    /**
     * {@inheritDoc}
     */
    public function getCustomHeaders(RequestInterface $request)
    {
        $headers = array();
        foreach ($this->customHeaders as $header) {
            if ($request->hasHeader($header)) {
                $headers[$header] = $request->getHeader($header);
            }
        }
        return $headers;
    }
}
