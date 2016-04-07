<?php

namespace Acquia\Hmac;

use Psr\Http\Message\RequestInterface;

class RequestAuthenticator implements RequestAuthenticatorInterface
{
    /**
     * @var \Acquia\Hmac\RequestSignerInterface
     */
    protected $requestSigner;

    /**
     * @var int|string
     */
    protected $expiry;

    /**
     * @param \Acquia\Hmac\RequestSignerInterface $requestSigner
     * @param int|string $expiry
     */
    public function __construct(RequestSignerInterface $requestSigner, $expiry)
    {
        $this->requestSigner = $requestSigner;
        $this->expiry        = $expiry;
    }

    /**
     * {inheritDoc}
     */
    public function authenticate(RequestInterface $request, KeyLoaderInterface $keyLoader)
    {
        // Get the signature passed through the HTTP request.
        $passedSignature = $this->requestSigner->getSignature($request);

        // Check whether the timestamp is valid.
        $comparison = $passedSignature->compareTimestamp($this->expiry);
        if (-1 == $comparison) {
            throw new Exception\TimestampOutOfRangeException('Request is too old');
        } elseif (1 == $comparison) {
            throw new Exception\TimestampOutOfRangeException('Request is too far in the future');
        }

        // Load the API Key and sign the request.
        if (!$key = $keyLoader->load($passedSignature->getId())) {
            throw new Exception\KeyNotFoundException('API key not found');
        }

        // Sign the request and check whether it matches the one that was
        // passed. If it matches, the request is authenticated.
        $requestSignature = $this->requestSigner->signRequest($request, $key->getSecret());
        if (!$passedSignature->matches($requestSignature)) {
            throw new Exception\InvalidSignatureException('Signature not valid');
        }

        return $key;
    }
}
