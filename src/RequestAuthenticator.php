<?php

namespace Acquia\Hmac;

class RequestAuthenticator implements RequestAuthenticatorInterface
{
    /**
     * @var \Acquia\Hmac\RequestSignerInterface
     */
    protected $requestSigner;

    /**
     * @var \Acquia\Hmac\RequestSignerInterface
     */
    protected $expiry;

    /**
     * @param \Acquia\Hmac\RequestSignerInterface $requestSigner
     * @param int|string $expiry
     */
    public function __construct(RequestSignerInterface $requestSigner, $expiry = '+15 minutes')
    {
        $this->requestSigner = $requestSigner;
        $this->expiry        = $expiry;
    }

    /**
     * @param \Acquia\Hmac\Request\RequestInterface $request
     * @param \Acquia\Hmac\KeyLoaderInterface $keyLoader
     *
     * @return true
     *
     * @throws \Acquia\Hmac\Exception\MalformedRequest
     * @throws \Acquia\Hmac\Exception\InvalidSignature
     */
    public function authenticate(Request\RequestInterface $request, KeyLoaderInterface $keyLoader)
    {
        // Get the signature passed through the HTTP request.
        $passedSignature = $this->requestSigner->getSignature($request);

        // Check whether the timestamp is valid.
        $comparison = $passedSignature->compareTimestamp($this->expiry);
        if (-1 == $comparison) {
            throw new Exception\InvalidSignature('Request is too old');
        } elseif (1 == $comparison) {
            throw new Exception\InvalidSignature('Request is too far in the future');
        }

        // Load the API Key and sign the request.
        if (!$key = $keyLoader->load($passedSignature->getId())) {
            throw new Exception\InvalidSignature('API key not valid');
        }

        // Sign the request and check whether it matches the one that was
        // passed. If it matches, the request is authenticated.
        $requestSignature = $this->signRequest($this->requestSigner, $request, $key->getSecret());
        return $passedSignature->matches($requestSignature);
    }
}
