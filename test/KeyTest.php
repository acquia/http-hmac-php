<?php

namespace Acquia\Hmac\Test;

use Acquia\Hmac\Key;
use Acquia\Hmac\KeyLoader;
use PHPUnit\Framework\TestCase;

/**
 * Tests the key for authenticating and signing requests.
 */
class KeyTest extends TestCase
{
    /**
     * Ensures the getters work as expected.
     */
    public function testGetters()
    {
        $id = 'efdde334-fe7b-11e4-a322-1697f925ec7b';
        $secret = 'W5PeGMxSItNerkNFqQMfYiJvH14WzVJMy54CPoTAYoI=';

        $key = new Key($id, $secret);

        $this->assertEquals($id, $key->getId());
        $this->assertEquals($secret, $key->getSecret());
    }

    public function testKeyLoaderOnLoadKeyId()
    {
        $id = 'efdde334-fe7b-11e4-a322-1697f925ec7b';
        $secret = 'W5PeGMxSItNerkNFqQMfYiJvH14WzVJMy54CPoTAYoI=';

        $loader = new KeyLoader([
            $id => $secret,
        ]);

        $this->assertEquals($id, $loader->load($id)->getId());
        $this->assertEquals($secret, $loader->load($id)->getSecret());
    }

    public function testKeyLoaderOnLoadInvalidKeyId()
    {
        $loader = new KeyLoader([]);

        $this->assertFalse($loader->load('invalid_id'));
    }
}
