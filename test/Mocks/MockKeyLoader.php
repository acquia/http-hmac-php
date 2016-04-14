<?php

namespace Acquia\Hmac\Test\Mocks;

use Acquia\Hmac\Key;
use Acquia\Hmac\KeyLoaderInterface;

class MockKeyLoader implements KeyLoaderInterface
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
