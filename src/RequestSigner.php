<?php

namespace Acquia\Hmac;

class RequestSigner implements RequestSignerInterface
{
    /**
     * @var string
     */
    protected $defaultAlgorithm;

    /**
     * @var array
     */
    protected $validAlgorithms;

    /**
     * @var string
     */
    protected $provider = 'Acquia';

    /**
     * @var array
     */
    protected $timestampHeaders = array('Date');

    /**
     * @param string $defaultAlgorithm
     * @param array $validAlgorithms
     */
    public function __construct($defaultAlgorithm = 'sha1', array $validAlgorithms = array('sha1', 'sha256'))
    {
        $this->defaultAlgorithm = $defaultAlgorithm;
        $this->validAlgorithms  = $validAlgorithms;
    }

    /**
     * {@inheritDoc}
     *
     * @throws \Acquia\Hmac\Exception\InvalidRequest
     */
    public function getSignature(Request\RequestInterface $request)
    {
        if (!$request->hasHeader('Authorization')) {
            throw new Exception\InvalidRequest('Authorization header required');
        }

        $provider = preg_quote($this->provider, '/');
        $pattern = '/^' . $provider . ' ([a-zA-Z0-9]+):([a-zA-Z0-9+/]+={0,2})$/';

        if (!preg_match($pattern, $request->getHeader('Authorization'), $matches)) {
            throw new Exception\InvalidRequest('Authorization header not valid');
        }

        return new Signature($matches[1], $matches[2]);
    }

    /**
     * {@inheritDoc}
     *
     * @throws \InvalidArgumentException
     * @throws \Acquia\Hmac\Exception\InvalidRequest
     */
    public function signRequest(Request\RequestInterface $request, $secretKey, $algorithm = null)
    {
        $algorithm = $algorithm ?: $this->defaultAlgorithm;

        if (!in_array($algorithm, hash_algos())) {
            throw new \InvalidArgumentException('Algorithm not supported by server: ' . $algorithm);
        }

        if (!in_array($algorithm, $this->validAlgorithms)) {
            throw new \InvalidArgumentException('Algorithm not valid: ' . $algorithm);
        }

        $digest = hash_hmac($algorithm, $this->getMessage($request), $secretKey, true);
        return base64_encode($digest);
    }

    /**
     * @param string $algorithm
     *
     * @return \Acquia\Hmac\Hash
     */
    public function setDefaultAlgorithm($algorithm)
    {
        $this->defaultAlgorithm = $algorithm;
        return $this;
    }

    /**
     * @return string
     */
    public function getDefaultAlgorithm()
    {
        return $this->defaultAlgorithm;
    }

    /**
     * @param array $algorithms
     *
     * @return \Acquia\Hmac\Hash
     */
    public function setValidAlgorithms(array $algorithms)
    {
        $this->validAlgorithms = $algorithms;
        return $this;
    }

    /**
     * @return array
     */
    public function getValidAlgorithms()
    {
        return $this->validAlgorithms;
    }

    /**
     * @param string $provider
     *
     * @return \Acquia\Hmac\Hash
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
     * @return \Acquia\Hmac\Hash
     */
    public function addTimestampHeader($header)
    {
        $this->timestampHeaders[] = $header;
        return $this;
    }

    /**
     * @param array $headers
     *
     * @return \Acquia\Hmac\Hash
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
     * Generates the message to be signed from the HTTP request.
     *
     * @param \Acquia\Hmac\Request\RequestInterface $request
     *
     * @return string
     *
     * @throws \Acquia\Hmac\Exception\InvalidRequest
     */
    public function getMessage(Request\RequestInterface $request)
    {
        $parts = array(
            $request->getMethod(),
            md5($request->getBody()),
            $this->getContentType($request),
            $this->getTimestamp($request),
            $request->getResource(),
        );

        return join("\n", $parts);
    }

    /**
     * @param \Acquia\Hmac\Request\RequestInterface $request
     *
     * @return string
     *
     * @throws \Acquia\Hmac\Exception\InvalidRequest
     */
    public function getTimestamp(Request\RequestInterface $request)
    {
        foreach ($this->timestampHeaders as $header) {
            if ($request->hasHeader($header)) {
                return $request->getHeader($header);
            }
        }

        if (count($this->timestampHeaders) > 1) {
            $message = 'At least one of the following headers is required: ' . join(', ' . $this->timestampHeaders);
        } else {
            $message = $this->timestampHeaders . ' header required';
        }

        throw new Exception\InvalidRequest($message);
    }

    /**
     * @param \Acquia\Hmac\Request\RequestInterface $request
     *
     * @return string
     *
     * @throws \Acquia\Hmac\Exception\InvalidRequest
     */
    public function getContentType(Request\RequestInterface $request)
    {
        if (!$request->hasHeader('Content-Type')) {
            throw new Exception\InvalidRequest('Content type header required');
        }

        return $request->getHeader('Content-Type');
    }
}
