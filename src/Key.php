<?php

namespace Acquia\Hmac;

/**
 * A key for authenticating and signing requests.
 */
class Key implements KeyInterface
{
    /**
     * @var string
     *   The key ID.
     */
    protected $id;

    /**
     * @var string
     *   The key secret.
     */
    protected $secret;

    /**
     * Initializes the key with a key ID and key secret.
     *
     * @param string $id
     *   The key ID.
     * @param string $secret
     *   The Base64-encoded key secret.
     */
    public function __construct($id, $secret)
    {
        $this->id = $id;
        $this->secret = $secret;
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
    public function getSecret()
    {
        return $this->secret;
    }
}
