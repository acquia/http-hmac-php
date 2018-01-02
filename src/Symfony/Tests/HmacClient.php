<?php

namespace Acquia\Hmac\Symfony\Tests;

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
     * Set Key for HMAC Auth
     *
     * @param Key $key
     * @return Key
     */
    public function setKey(Key $key) {

        $this->key = $key;

        return $this;

    }

    /**
     * Sign the request with HMAC HTTP and verify the response signature
     *
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return \Symfony\Component\HttpFoundation\Response
     * @throws \Exception
     */
    protected function doRequest($request)
    {

        if(!$this->key instanceof Key) {
            throw new \Exception("Key not provided");
        }

        $psr7Factory = new DiactorosFactory();
        $httpFoundationFactory = new HttpFoundationFactory();

        //convert the symfony request to PSR7 request
        $psrRequest = $psr7Factory->createRequest($request);

        //sign the request
        $hmacSigner = new RequestSigner($this->key);
        $signedRequest = $hmacSigner->signRequest($psrRequest);

        //convert back the signed PSR7 request to the symfony request
        $symfonyRequest = $httpFoundationFactory->createRequest($signedRequest);

        //send the request to the kernel and get the response
        $response = parent::doRequest($symfonyRequest);

        //convert the symfony response to psr7 response
        $psrResponse = $psr7Factory->createResponse($response);

        //init the authenticator and verify if the psr7 response signature is valid
        $authenticator = new ResponseAuthenticator($signedRequest, $this->key);

        if(!$authenticator->isAuthentic($psrResponse)) {
            throw new \Exception("The response cannot be authenticated !");
        }

        //return the symfony response
        return $response;
    }

}
