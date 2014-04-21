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
        $this->setValidAlgorithms($validAlgorithms);
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
     * {@inheritDoc}
     *
     * @throws \UnexpectedValueException
     */
    public function sign(Request\RequestInterface $request, $secretKey, $algorithm = null)
    {
        $algorithm = $algorithm ?: $this->defaultAlgorithm;

        if (!in_array($algorithm, hash_algos())) {
            throw new \UnexpectedValueException('Algorithm not supported by server: ' . $algorithm);
        }

        if (!in_array($algorithm, $this->validAlgorithms)) {
            throw new \UnexpectedValueException('Algorithm not valid: ' . $algorithm);
        }

        $digest = hash_hmac($algorithm, $this->getMessage($request), $secretKey, true);
        return base64_encode($digest);
    }

    /**
     * Generates the message to be signed from the HTTP request.
     *
     * @param \Acquia\Hmac\Request\RequestInterface $request
     *
     * @return string
     */
    public function getMessage(Request\RequestInterface $request)
    {
        $parts = array(
            $request->getMethod(),
            md5($request->getBody()),
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
     * @throws \UnderflowException
     */
    public function getTimestamp(Request\RequestInterface $request)
    {
        foreach ($this->timestampHeaders as $header) {
            if ($request->hasHeader($header)) {
                return $request->getHeader($header);
            }
        }

        // @todo Hash exception
        throw new \UnderflowException('Timestamp not found');
    }
}
