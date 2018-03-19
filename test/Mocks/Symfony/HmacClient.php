<?php

namespace Acquia\Hmac\Test\Mocks\Symfony;

use Acquia\Hmac\KeyInterface;
use Acquia\Hmac\RequestSigner;
use Acquia\Hmac\ResponseAuthenticator;
use Symfony\Bundle\FrameworkBundle\Client;
use Symfony\Bridge\PsrHttpMessage\Factory\DiactorosFactory;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;

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
     * @throws \Exception
     *   If the key has not been provided, or the respnonse cannot be authenticated.
     *
     * @return \Symfony\Component\HttpFoundation\Response
     *   An authenticated Symfony response.
     */
    protected function doRequest($request)
    {
        if (!$this->key instanceof Key) {
            throw new \Exception('HTTP HMAC key has not been provided.');
        }

        $psr7Factory = new DiactorosFactory();
        $httpFoundationFactory = new HttpFoundationFactory();

        $psrRequest = $psr7Factory->createRequest($request);

        $hmacSigner = new RequestSigner($this->key);
        $signedRequest = $hmacSigner->signRequest($psrRequest);
        $symfonyRequest = $httpFoundationFactory->createRequest($signedRequest);

        $response = parent::doRequest($symfonyRequest);
        $psrResponse = $psr7Factory->createResponse($response);

        $authenticator = new ResponseAuthenticator($signedRequest, $this->key);

        if (!$authenticator->isAuthentic($psrResponse)) {
            throw new \Exception('The response cannot be authenticated.');
        }

        return $response;
    }
}
