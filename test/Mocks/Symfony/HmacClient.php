<?php

namespace Acquia\Hmac\Test\Mocks\Symfony;

use Acquia\Hmac\Key;
use Acquia\Hmac\RequestSigner;
use Acquia\Hmac\ResponseAuthenticator;
use Symfony\Bundle\FrameworkBundle\Client;
use Symfony\Bridge\PsrHttpMessage\Factory\DiactorosFactory;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;

class HmacClient extends Client
{
    /**
     * @var Key
     */
    protected $key;

    /**
     * Set the private key for HTTP HMAC authentication.
     *
     * @param Key $key
     * @return Key
     */
    public function setKey(Key $key) {

        $this->key = $key;

        return $this;

    }

    /**
     * Sign the request with HTTP HMAC and verify the response signature.
     *
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return \Symfony\Component\HttpFoundation\Response
     * @throws \Exception
     */
    protected function doRequest($request)
    {
        if(!$this->key instanceof Key) {
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

        if(!$authenticator->isAuthentic($psrResponse)) {
            throw new \Exception('The response cannot be authenticated.');
        }

        return $response;
    }
}
