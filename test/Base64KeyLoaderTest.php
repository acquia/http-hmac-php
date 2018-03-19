<?php

namespace Acquia\Hmac\Test;

use Acquia\Hmac\Base64KeyLoader;
use PHPUnit\Framework\TestCase;

/**
 * Tests the key for authenticating and signing requests.
 */
class Base64KeyLoaderTest extends TestCase
{
    /**
     * Ensures the key loader correctly encodes secrets.
     */
     public function testLoad()
     {
         $id     = '615d6517-1cea-4aa3-b48e-96d83c16c4dd';
         $secret = 'My Secret Key That is Very Secure';

         $loader = new Base64KeyLoader([
             $id => $secret,
         ]);

         $this->assertEquals(base64_encode($secret), $loader->load($id)->getSecret());
     }

     public function testLoadOnKeyIsNotFound()
     {
        $loader = new Base64KeyLoader([]);

        $this->assertFalse($loader->load('invalid_id'));
     }
}
