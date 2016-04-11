<?php

namespace Acquia\Hmac\Digest;

interface DigestInterface
{
    /**
     * Returns the signature.
     *
     * @param string $message
     *   The message to sign.
     * @param string $secretKey
     *   The key with which to sign the message.
     *
     * @return string
     *   The signed message.
     */
    public function sign($message, $secretKey);

    /**
     * Hashes a string based using the digest's algorithm.
     *
     * @param string $message
     *   The message to hash.
     *
     * @param string
     *   The hashed message.
     */
    public function hash($message);
}
