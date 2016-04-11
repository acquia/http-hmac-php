<?php

namespace Acquia\Hmac\Test;

use Acquia\Hmac\Key;

/**
 * Tests the key for authenticating and signing requests.
 */
class KeyTest extends \PHPUnit_Framework_TestCase
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
}
