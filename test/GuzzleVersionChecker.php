<?php
/**
 * Created by PhpStorm.
 * User: lisa.backer
 * Date: 8/31/15
 * Time: 3:00 PM
 */

namespace Acquia\Hmac\Test;


class GuzzleVersionChecker {
  public static function hasGuzzle5() {
    return class_exists('GuzzleHttp\Message\Request');
  }

  public static function hasGuzzle6() {
    return class_exists('GuzzleHttp\Psr7\Request');
  }
}
