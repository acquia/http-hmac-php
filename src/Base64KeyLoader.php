<?php

namespace Acquia\Hmac;

/**
 * Base64KeyLoader class for loading keys and Base64 encoding them.
 *
 * These keys can be later used for signing and verifying requests.
 */
class Base64KeyLoader extends KeyLoader
{
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
