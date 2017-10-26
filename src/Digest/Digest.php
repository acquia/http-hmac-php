<?php

namespace Acquia\Hmac\Digest;

class Digest implements DigestInterface
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
     * {@inheritDoc}
     */
    public function sign($message, $secretKey)
    {
        // The Acquia HMAC spec requires that we use MIME Base64 encoded
        // secrets, but PHP requires them to be decoded before signing.
        $digest = hash_hmac($this->algorithm, $message, base64_decode($secretKey, true), true);

        return base64_encode($digest);
    }


    /**
     * {@inheritDoc}
     */
    public function hash($message)
    {
        return base64_encode(hash($this->algorithm, $message, true));
    }
}
