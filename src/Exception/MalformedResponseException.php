<?php

namespace Acquia\Hmac\Exception;

/**
 * Exception thrown when a response cannot be authenticated due to a missing or
 * malformed header.
 */
class MalformedResponseException extends InvalidRequestException
{
}
