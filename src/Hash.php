<?php

namespace Acquia\Hmac;

class Hash
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
    public function __construct($defaultAlgorithm = 'sha256', array $validAlgorithms = array('sha1', 'sha256', 'sha512'))
    {
        $this->setValidAlgorithms($validAlgorithms);
        $this->setDefaultAlgorithm($defaultAlgorithm);
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
     * @param string $algorithm
     *
     * @return bool
     *
     * @throws \UnexpectedValueException
     */
    public function algorithmValid($algorithm)
    {
        if (!in_array($algorithm, hash_algos())) {
            throw new \UnexpectedValueException('Unsupported algorithm: ' . $algorithm);
        }

        return in_array($algorithm, $this->validAlgorithms());
    }

    /**
     * @param string $algorithm
     *
     * @return \Acquia\Hmac\Hash
     *
     * @throws \UnexpectedValueException
     */
    public function setDefaultAlgorithm($algorithm)
    {
        if (!$this->algorithmValid($algorithm)) {
            throw new \UnexpectedValueException('Invalid algorithm: ' . $algorithm);
        }

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
     * @param \Acquia\Hmac\Request\RequestInterface $request
     *
     * @return string
     */
    public function get(Request\RequestInterface $request)
    {
        $hash = hash_hmac($this->algorithm, $this->getMessage($request), $this->key, true);
        return base64_encode($hash);
    }

    /**
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
