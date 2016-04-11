<?php

namespace Acquia\Hmac;

use Acquia\Hmac\Exception\InvalidSignatureException;
use Acquia\Hmac\Exception\KeyNotFoundException;
use Acquia\Hmac\Exception\MalformedRequestException;
use Acquia\Hmac\Exception\TimestampOutOfRangeException;
use Psr\Http\Message\RequestInterface;

class RequestAuthenticator implements RequestAuthenticatorInterface
{
    /**
     * @var \Acquia\Hmac\KeyLoaderInterface
     *   The key loader.
     */
    protected $keyLoader;

    /**
     * @var int|string
     *   The amount of time drift requests can be made when compared to the server.
     */
    protected $expiry;

    /**
     * @param \Acquia\Hmac\KeyLoaderInterface $keyLoader
     *   A datastore used to locate secrets for corresponding IDs.
     */
    public function __construct(KeyLoaderInterface $keyLoader)
    {
        $this->keyLoader = $keyLoader;
        $this->expiry    = '+15 min';
    }

    /**
     * {@inheritDoc}
     */
    public function authenticate(RequestInterface $request)
    {

        $authHeader = AuthorizationHeader::createFromRequest($request);
        $signature = $authHeader->getSignature();

        // Check whether the timestamp is valid.
        $comparison = $this->compareTimestamp($request, $this->expiry);

        if (-1 == $comparison) {
            throw new TimestampOutOfRangeException('Request is too old');
        } elseif (1 == $comparison) {
            throw new TimestampOutOfRangeException('Request is too far in the future');
        }

        // Load the API Key and sign the request.
        if (!$key = $this->keyLoader->load($authHeader->getId())) {
            throw new KeyNotFoundException('API key not found');
        }

        // Generate the signature from the passed authorization header.
        // If it matches the request signature, the request is authenticated.
        $compareRequest = $request->withoutHeader('Authorization');


        $authHeaderBuilder = new AuthorizationHeaderBuilder($compareRequest, $key);
        $authHeaderBuilder->setRealm($authHeader->getRealm());
        $authHeaderBuilder->setId($authHeader->getId());
        $authHeaderBuilder->setNonce($authHeader->getNonce());
        $authHeaderBuilder->setVersion($authHeader->getVersion());
        $authHeaderBuilder->setCustomHeaders($authHeader->getCustomHeaders());

        $compareAuthHeader = $authHeaderBuilder->getAuthorizationHeader();
        $compareSignature = $compareAuthHeader->getSignature();


        if ($signature !== $compareSignature) {
            print PHP_EOL . implode(PHP_EOL, [
                '----------------------------',
                'Authent timestamp: ' . $request->getHeaderLine('X-Authorization-Timestamp'),
                'Compare timestamp: ' . $compareRequest->getHeaderLine('X-Authorization-Timestamp'),
                (string) $authHeader,
                (string) $compareAuthHeader,
                '----------------------------',
            ]);


            throw new InvalidSignatureException('Signature not valid');
        }

        return $key;
    }

    /**
     * Retrieves the request signer.
     *
     * @param \Acquia\Hmac\KeyInterface $key
     *   The key with which to sign requests.
     *
     * @return \Acquia\Hmac\RequestSignerInterface
     *   The request signer.
     */
    protected function getRequestSigner(KeyInterface $key)
    {
        return new RequestSigner($key);
    }

    /**
     * Retrieves the current timestamp.
     *
     * This is provided as a method to allow mocking during unit tests.
     *
     * @return int
     *   The current timestamp.
     */
    protected function getCurrentTimestamp()
    {
        return time();
    }


    /**
     * {@inheritDoc}
     *
     * @throws \InvalidArgumentException
     */
    protected function compareTimestamp(RequestInterface $request, $expiry)
    {
        if (!$request->hasHeader('X-Authorization-Timestamp')) {
            throw new MalformedRequestException('Request is missing X-Authorization-Timestamp.');
        }

        $timestamp = (int) $request->getHeaderLine('X-Authorization-Timestamp');
        $current   = $this->getCurrentTimestamp();

        // Is the request too old?
        $lowerLimit = $this->getExpiry($expiry, $timestamp);
        if ($current > $lowerLimit) {
            return -1;
        }

        // Is the request too far in the future?
        $upperLimit = $this->getExpiry($expiry, $current);
        if ($timestamp > $upperLimit) {
            return 1;
        }

        // Timestamp is within the expected range.
        return 0;
    }

    /**
     * Retrieves the request expiry as a timestamp.
     *
     * @param int|string $expiry
     *   The passed expiry.
     * @param int $relativeTimestamp
     *   The timestamp from which to base the expiry.
     *
     * @return int
     *   The expiry as a timestamp.
     *
     */
    protected function getExpiry($expiry, $relativeTimestamp)
    {
        if (!is_int($expiry)) {
            $expiry = strtotime($expiry, $relativeTimestamp);
        }

        return $expiry;
    }
}
