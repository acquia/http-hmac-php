<?php

namespace Acquia\Hmac\Digest;

use Acquia\Hmac\RequestSignerInterface;
use Acquia\Hmac\Request\RequestInterface;

abstract class DigestAbstract implements DigestInterface
{
    /**
     * @var string
     */
    protected $algorithm;

    /**
     * @param string $algorithm
     */
    public function __construct($algorithm = 'sha1')
    {
        $this->algorithm = $algorithm;
    }

    /**
     * @param string $algorithm
     *
     * @return \Acquia\Hmac\Digest\DigestAbstract
     */
    public function setAlgorithm($algorithm)
    {
        $this->algorithm = $algorithm;
        return $this;
    }

    /**
     * @return string
     */
    public function getAlgorithm()
    {
        return $this->algorithm;
    }

    /**
     * {@inheritDoc}
     */
    public function get(RequestSignerInterface $requestSigner, RequestInterface $request, $secretKey)
    {
        $message = $this->getMessage($requestSigner, $request);
        $digest = hash_hmac($this->algorithm, $message, $secretKey, true);
        return base64_encode($digest);
    }

    /**
     * Returns the message being signed.
     *
     * @param \Acquia\Hmac\RequestSignerInterface $requestSigner
     * @param \Acquia\Hmac\Request\RequestInterface $request
     *
     * @return string
     */
    abstract protected function getMessage(RequestSignerInterface $requestSigner, RequestInterface $request);
}
