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
     * @param \Exception|null $previous
     *   The previous exception.
     * @param int $code
     *   The exception code.
     * @param \Psr\Http\Message\RequestInterface|null $request
     *   The request.
     */
    public function __construct($message = "", \Exception $previous = null, $code = 0, RequestInterface $request = null)
    {
        parent::__construct($message, $code, $previous);
        $this->request = $request;
    }

    /**
     * Returns the request.
     *
     * @return RequestInterface
     */
    public function getRequest()
    {
        return $this->request;
    }

    /**
     * Sets the request.
     *
     * @param RequestInterface $request
     */
    public function setRequest($request)
    {
        $this->request = $request;
    }
}
