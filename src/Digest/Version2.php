<?php

namespace Acquia\Hmac\Digest;

use Acquia\Hmac\Exception;
use Acquia\Hmac\RequestSignerInterface;
use Acquia\Hmac\AuthorizationHeaderInterface;
use Psr\Http\Message\RequestInterface;

class Version2 extends DigestAbstract
{
    /**
     * {@inheritDoc}
     */
    public function getMessage(RequestSignerInterface $requestSigner, RequestInterface $request, $secretKey)
    {
        $parts = array(
            $this->getMethod($request),
            $this->getHost($request),
            $this->getPath($request),
            $this->getQueryParameters($request),
            $this->getAuthorizationHeaders($requestSigner, $request),
        );

        // Add in the signed headers.
        $auth_header_params = $this->getSignedHeaders($requestSigner, $request);
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
    protected function getMethod(RequestInterface $request)
    {
        return strtoupper($request->getMethod());
    }

    /**
     * Returns the request body.
     *
     * @param \Psr\Http\Message\RequestInterface $request
     *
     * @return string
     */
    protected function getBody(RequestInterface $request)
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
    public function getHashedBody(RequestInterface $request)
    {
        $digest = base64_encode(hash($this->getAlgorithm(), $request->getBody(), true));
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

    /**
     * Returns host and port if available.
     *
     * @param \Psr\Http\Message\RequestInterface $request
     *
     * @return string
     */
    public function getHost(RequestInterface $request)
    {
        $host = $request->getUri()->getHost();
        if ($port = $request->getUri()->getPort()) {
            $host .= ':' . $port;
        }
        return $host;
    }

    /**
     * Returns path of the request.
     *
     * @param \Psr\Http\Message\RequestInterface $request
     *
     * @return string
     */
    public function getPath(RequestInterface $request)
    {
        return $request->getUri()->getPath();
    }

    /**
     * Returns query string parameters of the request.
     *
     * @param \Psr\Http\Message\RequestInterface $request
     *
     * @return string
     */
    public function getQueryParameters(RequestInterface $request)
    {
        return $request->getUri()->getQuery();
    }

    /**
     * Returns the signed headers and their values according to the spec.
     *
     * This is a newline-delimited list of the signed request headers and their
     * values in the format "header:value\n".
     *
     * @param \Acquia\Hmac\RequestSignerInterface $requestSigner
     * @param \Psr\Http\Message\RequestInterface $request
     *
     * @return string
     */
    public function getSignedHeaders(RequestSignerInterface $requestSigner, RequestInterface $request)
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

    /**
     * Returns the authorization headers according to the spec.
     *
     * This is a commma-delimited list of ID, nonce, realm and version with
     * their values.
     *
     * @param \Acquia\Hmac\RequestSignerInterface $requestSigner
     *
     * @return string
     */
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
