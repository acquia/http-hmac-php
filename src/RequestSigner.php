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

        // Check the provider.
        $header = $request->getHeader('Authorization');
        if ($pos = strpos($header, $this->provider . ' ') === false) {
            throw new Exception\MalformedRequestException('Invalid provider in authorization header');
        }

        // Split ID and sgnature by an unescaped colon.
        $offset = strlen($this->provider) + 1;
        $credentials = substr($header, $offset);
        $matches = preg_split('@\\\\.(*SKIP)(*FAIL)|:@s', $credentials);
        if (!isset($matches[1])) {
            throw new Exception\MalformedRequestException('Unable to parse ID and signature from authorization header');
        }

        // Ensure the signature is a base64 encoded string.
        if (!preg_match('@^[a-zA-Z0-9+/]+={0,2}$@', $matches[1])) {
            throw new Exception\MalformedRequestException('Invalid signature in authorization header');
        }

        $time = $this->getTimestamp($request);
        $timestamp = strtotime($time);
        if (!$timestamp) {
            throw new Exception\MalformedRequestException('Timestamp not valid');
        }

        return new Signature(stripslashes($matches[0]), $matches[1], $timestamp);
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
        return $this->provider . ' ' . str_replace(':', '\\:', $id) . ':' . $signature;
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
