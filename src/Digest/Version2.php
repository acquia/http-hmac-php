<?php

namespace Acquia\Hmac\Digest;

use Acquia\Hmac\Exception;
use Acquia\Hmac\RequestSignerInterface;
use Acquia\Hmac\AuthorizationHeaderInterface;
use Psr\Http\Message\RequestInterface;

// @TODO 3.0 This class should be Version2
class Version2 extends DigestAbstract
{
    /**
     * {@inheritDoc}
     */
    // @TODO 3.0 make this public and test it with the fixtures
    public function getMessage(RequestSignerInterface $requestSigner, RequestInterface $request, $secretKey)
    {
        $parts = array(
            // @TODO 3.0 Message format has changed
            // @TODO 3.0 This will also require changes to the RequestInterface:
            $this->getMethod($request),
            $this->getHost($request),
            $this->getPath($request),
            $this->getQueryParameters($request),
            $this->getAuthorizationHeaders($requestSigner, $request),
        );

        // Add in the signed headers.
        $auth_header_params = $this->getAuthorizationHeaderParameters($requestSigner, $request);
        if (!empty($auth_header_params)) {
            $parts[] = $auth_header_params;
        }

        $parts[] = $this->getTimestamp($requestSigner, $request);

        // Guzzle PSR7 gives us a stream that can be cast to a string.
        $body = (string) $this->getBody($request);
        if (!empty($body)) {
            $parts[] = $this->getContentType($requestSigner, $request);
            $parts[] = $this->getHashedBody($request);
        }

        $message = join("\n", $parts);
        return $message;
    }

    /**
     * Returns the normalized HTTP mthod, e.g. GET, POST, etc.
     *
     * @param \Psr\Http\Message\RequestInterface $request
     *
     * @return string
     */
    protected function getMethod(RequestInterface$request)
    {
        return strtoupper($request->getMethod());
    }

    // @TODO 3.0 Document
    protected function getBody(RequestInterface$request)
    {
        return $request->getBody();
    }

    /**
     * Returns the sha256 hash of the HTTP request body.
     *
     * @param \Psr\Http\Message\RequestInterface $request
     *
     * @return string
     */
    public function getHashedBody(RequestInterface$request)
    {
        // @TODO 3.0 base64 encoded SHA-256 digest of the raw body of the HTTP request,
        // @TODO 3.0 Send the X-Authorization-Content-SHA256 header with requests.
        // for POST, PUT, PATCH, DELETE or other requests that may have a body. Omit if
        // Content-Length is 0. This should be identical to the string sent as the
        // X-Authorization-Content-SHA256 header.
        $digest = base64_encode(hash('sha256', $request->getBody(), true));
        return $digest;
    }

    /**
     * Returns the normalized value of the "Content-type" header.
     *
     * @param \Acquia\Hmac\RequestSignerInterface $requestSigner
     * @param \Psr\Http\Message\RequestInterface $request
     *
     * @return string
     */
    protected function getContentType(RequestSignerInterface $requestSigner, RequestInterface $request)
    {
        $type = strtolower($requestSigner->getContentType($request));
        return is_null($type) ? '' : $type;
    }

    // @TODO 3.0 Document
    public function getHost(RequestInterface$request)
    {
        $host = $request->getUri()->getHost();
        if ($port = $request->getUri()->getPort()) {
            $host .= ':' . $port;
        }
        return $host;
    }

    // @TODO 3.0 Document
    public function getPath(RequestInterface$request)
    {
        return $request->getUri()->getPath();
    }

    // @TODO 3.0 Document
    public function getQueryParameters(RequestInterface$request)
    {
        return $request->getUri()->getQuery();
    }

    // @TODO 3.0 Document
    // @TODO 3.0 Interface?
    public function getAuthorizationHeaderParameters(RequestSignerInterface $requestSigner, RequestInterface $request)
    {
        $header_message = '';
        foreach ($requestSigner->getAuthorizationHeader()->getSignedHeaders() as $key) {
            if (!empty($key)) {
                $value = $request->getHeaderLine($key);
                $header_message .= strtolower($key) . ':' . $value . "\n";
            }
        }
        return trim($header_message, "\n");
    }

    // @TODO 3.0 Document
    // @TODO 3.0 Interface?
    public function getAuthorizationHeaders(RequestSignerInterface $signer)
    {
        return sprintf(
            'id=%s&nonce=%s&realm=%s&version=%s',
            $signer->getAuthorizationHeader()->getId(),
            $signer->getAuthorizationHeader()->getNonce(),
            rawurlencode($signer->getAuthorizationHeader()->getRealm()),
            $signer->getAuthorizationHeader()->getVersion()
        );
    }

    /**
     * Returns the value of the "Timestamp" header.
     *
     * @param \Acquia\Hmac\RequestSignerInterface $requestSigner
     * @param \Psr\Http\Message\RequestInterface $request
     *
     * @return string
     */
    protected function getTimestamp(RequestSignerInterface $requestSigner, RequestInterface $request)
    {
        return $requestSigner->getTimestamp($request);
    }
}
