<?php

namespace Acquia\Hmac;

/**
 * Base64KeyLoader class for loading keys and Base64 encoding them.
 *
 * These keys can be later used for signing and verifying requests.
 */
class Base64KeyLoader implements KeyLoaderInterface
{
    /**
     * @var array
     *   Array of provided keys.
     */
    protected $keys = [];

    /**
     * Initialize keys with provided pairs.
     *   @param array $keys
     */
    public function __construct(array $keys = [])
    {
        $this->keys = $keys;
    }

    /**
     * {@inheritDoc}
     */
    public function load($id)
    {
        if (!isset($this->keys[$id])) {
            return false;
        }

        return new Key($id, base64_encode($this->keys[$id]));
    }
}
