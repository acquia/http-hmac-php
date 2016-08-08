<?php

namespace Acquia\Hmac;

use Acquia\Hmac\Exception\MalformedResponseException;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 *
 */
class ResponseAuthenticator
{
    /**
     * @var \Psr\Http\Message\RequestInterface $request
     *   The signed request.
     */
    protected $request;

    /**
     * @param \Acquia\Hmac\KeyInterface $key
     *   The key with which the request was signed.
     */
    protected $key;

    /**
     * Initializes the response authenticator with a request and auth key.
     *
     * @param \Psr\Http\Message\RequestInterface $request
     *   The signed request.
     * @param \Acquia\Hmac\KeyInterface $key
     *   The key with which the request was signed.
     */
    public function __construct(RequestInterface $request, KeyInterface $key)
    {
        $this->request = $request;
        $this->key = $key;
    }

    /**
     * {@inheritDoc}
     */
    public function isAuthentic(ResponseInterface $response)
    {
        if (!$response->hasHeader('X-Server-Authorization-HMAC-SHA256')) {
            throw new MalformedResponseException(
                'Response is missing required X-Server-Authorization-HMAC-SHA256 header.',
                null,
                0,
                $response
            );
        }

        $responseSigner = new ResponseSigner($this->key, $this->request);
        $compareResponse = $responseSigner->signResponse(
            $response->withoutHeader('X-Server-Authorization-HMAC-SHA256')
        );

        $responseSignature = $response->getHeaderLine('X-Server-Authorization-HMAC-SHA256');
        $compareSignature =  $compareResponse->getHeaderLine('X-Server-Authorization-HMAC-SHA256');

        return hash_equals($compareSignature, $responseSignature);
    }
}
