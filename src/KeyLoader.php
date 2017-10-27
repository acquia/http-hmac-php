<?php

namespace Acquia\Hmac;

/**
 * KeyLoader class for loading keys.
 *
 * These keys can be later used for signing and verifying requests.
 */
class KeyLoader implements KeyLoaderInterface
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

        return new Key($id, $this->keys[$id]);
    }
}
