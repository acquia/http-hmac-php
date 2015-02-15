<?php

namespace Acquia\Hmac;

interface SignatureInterface
{
    /**
     * Returns the key's ID.
     *
     * @return string
     */
    public function getId();

    /**
     * Returns the signature.
     *
     * @return string
     */
    public function getSignature();

    /**
     * Returns the timestamp.
     * @return integer
     */
    public function getTimestamp();

    /**
     * Returns true if the signature matches the passed string
     *
     * @param string $signature
     *
     * @return bool
     */
    public function matches($signature);

    /**
     * Compares the request's timestamp to the expiry to see whether it is in
     * the expected range.
     *
     * Returns 0 if the timestamp is within the expected range, -1 if the
     * request is too old, 1 if the request is too far in the future.
     *
     * @param int|string $expiry
     *
     * @return string
     */
    public function compareTimestamp($expiry);

    /**
     * Returns the signature.
     *
     * @return string
     */
    public function __toString();
}
