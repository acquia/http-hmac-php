<?php

namespace Acquia\Hmac\Test;

use Acquia\Hmac\KeyLoaderInterface;

class DummyKeyLoader implements KeyLoaderInterface
{
    protected $keys = array();

    public function __construct() {
        $this->keys = array(
          'efdde334-fe7b-11e4-a322-1697f925ec7b' => 'W5PeGMxSItNerkNFqQMfYiJvH14WzVJMy54CPoTAYoI=',
          '615d6517-1cea-4aa3-b48e-96d83c16c4dd' => 'TXkgU2VjcmV0IEtleSBUaGF0IGlzIFZlcnkgU2VjdXJl',
        );
    }

    /**
     * {@inheritDoc}
     */
    public function load($id)
    {
        if (!isset($this->keys[$id])) {
            return false;
        }

        return new DummyKey($id, $this->keys[$id]);
    }
}
