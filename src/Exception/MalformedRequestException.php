<?php

namespace Acquia\Hmac\Exception;

/**
 * Exception thrown when a request cannot be authenticated due to a missing or
 * malformed header.
 */
class MalformedRequestException extends InvalidRequestException
{
}
