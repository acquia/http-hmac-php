<?php

namespace Acquia\Hmac\Test;

use Acquia\Hmac\Key;
use Acquia\Hmac\KeyLoaderInterface;

class DummyKeyLoader implements KeyLoaderInterface
{
    protected $keys = [];

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
