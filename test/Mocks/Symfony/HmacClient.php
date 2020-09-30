<?php

namespace Acquia\Hmac\Test\Mocks\Symfony;

use Acquia\Hmac\KeyInterface;
use Acquia\Hmac\RequestSigner;
use Acquia\Hmac\ResponseAuthenticator;
use Nyholm\Psr7\Factory\Psr17Factory;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
use Symfony\Bundle\FrameworkBundle\Client;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;
use Symfony\Component\HttpFoundation\Response;

/**
 * A mock Symfony client for testing HTTP HMAC request signing and response authentication.
 */
class HmacClient extends Client
{
    /**
     * @var \Acquia\Hmac\KeyInterface $key
     *   The key to sign requests with.
     */
    protected $key;

    /**
     * Set the private key for HTTP HMAC authentication.
     *
     * @param \Acquia\Hmac\KeyInterface $key
     *   The key to sign requests with.
     *
     * @return static
     */
    public function setKey(KeyInterface $key)
    {
        $this->key = $key;

        return $this;
    }

    /**
     * Sign the request with HTTP HMAC and authenticate the response signature.
     *
     * @param \Symfony\Component\HttpFoundation\Request $request
     *   The Symfony request.
     *
     * @return \Symfony\Component\HttpFoundation\Response
     *   An Symfony response indicating the result of making the signed request.
     */
    protected function doRequest($request)
    {
        if (!$this->key instanceof KeyInterface) {
            return new Response('The HTTP HMAC key has not been provided.', 400);
        }

        $psr17Factory = new Psr17Factory();
        $psr7Factory = new PsrHttpFactory($psr17Factory, $psr17Factory, $psr17Factory, $psr17Factory);
        $httpFoundationFactory = new HttpFoundationFactory();

        $psrRequest = $psr7Factory->createRequest($request);

        $hmacSigner = new RequestSigner($this->key);
        $signedRequest = $hmacSigner->signRequest($psrRequest);
        $symfonyRequest = $httpFoundationFactory->createRequest($signedRequest);

        $response = parent::doRequest($symfonyRequest);
        $psrResponse = $psr7Factory->createResponse($response);

        $authenticator = new ResponseAuthenticator($signedRequest, $this->key);

        if (!$authenticator->isAuthentic($psrResponse)) {
            return new Response('The response cannot be authenticated.', 400);
        }

        return $response;
    }
}
