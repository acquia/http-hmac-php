<?php

namespace Acquia\Hmac\Exception;

use Psr\Http\Message\ResponseInterface;

/**
 * Exception thrown when a response cannot be authenticated due to a missing or
 * malformed header.
 */
class MalformedResponseException extends InvalidRequestException
{
    /**
     * @var ResponseInterface
     */
    private $response;

    /**
     * Creates a new MalformedResponseException instance.
     *
     * @param string $message
     *   The exception message.
     * @param \Exception|null $previous
     *   The previous exception.
     * @param int $code
     *   The exception code.
     * @param \Psr\Http\Message\ResponseInterface|null $response
     *   The response.
     */
    public function __construct(
        $message = "",
        \Exception $previous = null,
        $code = 0,
        ResponseInterface $response = null
    ) {
        parent::__construct($message, $code, $previous);
        $this->response = $response;
    }

    /**
     * Returns the response.
     *
     * @return ResponseInterface
     */
    public function getResponse()
    {
        return $this->response;
    }

    /**
     * Sets the response.
     *
     * @param ResponseInterface $response
     */
    public function setResponse($response)
    {
        $this->response = $response;
    }
}
