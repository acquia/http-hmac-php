<?php

namespace Acquia\Hmac;

class Signature implements SignatureInterface
{
    /**
     * @var string
     */
    protected $id;

    /**
     * @var string
     */
    protected $signature;

    /**
     * @var int
     */
    protected $timestamp;

    /**
     * @param string $id
     * @param string $signature
     * @param int $timestamp
     */
    public function __construct($id, $signature, $timestamp)
    {
        $this->id        = $id;
        $this->signature = $signature;
        $this->timestamp = $timestamp;
    }

    /**
     * {@inheritDoc}
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * {@inheritDoc}
     */
    public function getSignature()
    {
        return $this->signature;
    }

    /**
     * {@inheritDoc}
     */
    public function getTimestamp()
    {
        return $this->timestamp;
    }

    /**
     * {@inheritDoc}
     */
    public function matches($signature)
    {
        return $this->signature === (string) $signature;
    }

    /**
     * {@inheritDoc}
     *
     * @throws \InvalidArgumentException
     */
    public function compareTimestamp($expiry)
    {
        // There is no expiry.
        if (!$expiry) {
            return 0;
        }

        // Is the request too old?
        $lowerLimit = $this->getExpiry($expiry, $this->timestamp);
        if (time() > $lowerLimit) {
            return -1;
        }

        // Is the request too far in the future?
        $upperLimit = $this->getExpiry($expiry, time());
        if ($this->timestamp > $upperLimit) {
            return 1;
        }

        // Timestamp is within the expected range.
        return 0;
    }

    /**
     * {@inheritDoc}
     */
    public function __toString()
    {
        return $this->signature;
    }

    /**
     * @param int|string $expiry
     * @param int $relativeTimestamp
     *
     * @throws \InvalidArgumentException
     */
    protected function getExpiry($expiry, $relativeTimestamp)
    {
        if (!is_int($expiry)) {
            $expiry = strtotime($expiry, $relativeTimestamp);
            if (!$expiry) {
                throw new \InvalidArgumentException('Expiry not valid');
            }
        }

        return $expiry;
    }
}
