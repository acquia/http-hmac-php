<?php

namespace Acquia\Hmac\Digest;

use Acquia\Hmac\RequestSignerInterface;
use Psr\Http\Message\RequestInterface;

abstract class DigestAbstract implements DigestInterface
{
    /**
     * @var string
     */
    protected $algorithm;

    /**
     * @param string $algorithm
     */
    public function __construct($algorithm = 'sha256')
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
        $message = $this->getMessage($requestSigner, $request, $secretKey);
        // The Acquia HMAC spec requires that we use MIME base64 encoded
        // secrets, but PHP requires them to be decoded before signing.
        $digest = hash_hmac($this->algorithm, $message, base64_decode($secretKey), true);
        return base64_encode($digest);
    }

    /**
     * Returns the message being signed.
     *
     * @param \Acquia\Hmac\RequestSignerInterface $requestSigner
     * @param \Psr\Http\Message\RequestInterface $request
     * @param string $secretKey
     *
     * @return string
     */
    abstract public function getMessage(
        RequestSignerInterface $requestSigner,
        RequestInterface $request,
        $secretKey
    );
}
