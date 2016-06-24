<?php

namespace Acquia\Hmac\Exception;

use Psr\Http\Message\RequestInterface;

/**
 * Exception thrown when a request cannot be authenticated due to a missing or
 * malformed header.
 */
class MalformedRequestException extends InvalidRequestException
{
    /**
     * @var RequestInterface
     */
    private $request;

    /**
     * Creates a new MalformedRequestException instance.
     *
     * @param string $message
     *   The exception message.
     * @param \Psr\Http\Message\RequestInterface|null $request
     *   The request.
     * @param int $code
     *   The exception code.
     * @param \Exception|NULL $previous
     *   The previous exception.
     */
    public function __construct($message = "", RequestInterface $request = null, $code = 0, \Exception $previous = null)
    {
        parent::__construct($message, $code, $previous);
        $this->request = $request;
    }

    /**
     * Returns the response.
     *
     * @return RequestInterface
     */
    public function getRequest()
    {
        return $this->request;
    }

    /**
     * Sets the response.
     *
     * @param RequestInterface $request
     */
    public function setRequest($request)
    {
        $this->request = $request;
    }
}
