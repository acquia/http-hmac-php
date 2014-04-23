<?php

namespace Acquia\Hmac\Exception;

/**
 * Exception thrown for requests that are properly formed but are not
 * authenticated due to an invalid signature or timestamp that is out of range.
 */
class InvalidSignature extends InvalidRequest {}
