<?php

namespace Acquia\Hmac\Digest;

use Acquia\Hmac\Exception;
use Acquia\Hmac\RequestSignerInterface;
use Psr\Http\Message\RequestInterface;

// @TODO 3.0 This class should be Version2
class Version2 extends DigestAbstract
{
    /**
     * {@inheritDoc}
     */
    protected function getMessage(RequestSignerInterface $requestSigner, RequestInterface $request, $secretKey)
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

        // Omit if there is no request body.
        // @TODO 3.0 The string cast is because the HmacAuthMiddleware::signRequest method takes a Psr RequestInterface and uses this api, however the getBody method returns a stream. This can be cast to a string here, but this is wrong. the signRequest method should really take an acquia RequestInterface object.
        // @TODO 3.0 the ruby implementation just looks for the X-Authorization-Content-SHA256 header, should we do the same?
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
    public function getHost(RequestInterface$request) {
        $host = $request->getUri()->getHost();
        if ($port = $request->getUri()->getPort()) {
            $host .= ':' . $port;
        }
        return $host;
    }

    // @TODO 3.0 Document
    public function getPath(RequestInterface$request) {
        return $request->getUri()->getPath();
    }

    // @TODO 3.0 Document
    public function getQueryParameters(RequestInterface$request) {
        return $request->getUri()->getQuery();
    }

    // @TODO 3.0 Document
    // @TODO 3.0 Interface?
    public function getAuthorizationHeaderParameters(RequestSignerInterface $requestSigner, RequestInterface $request) {
        // @TODO 3.0 better AuthHeader handling, probably new class
        $headers = array();
        $header_message = '';

        // @TODO 3.0 in general, we need better differentiation of signing in the client vs server.
        $signer_headers = $requestSigner->getCustomHeaders($request);
        if (!empty($signer_headers)) {
            $headers = array_keys($signer_headers);
        } else {
            $header = $request->getHeaderLine('Authorization');
            if (!empty($header)) {
                foreach (explode(',', $header) as $auth) {
                    $auth_parts = explode(':', $auth);
                    if (count($auth_parts) < 2) {
                        continue;
                    }
                    // @TODO 3.0 better quote replacement.
                    $key = trim($auth_parts[0], " '\"");
                    $value = trim($auth_parts[1], " '\"");
                    if ($key == 'headers') {
                        $headers = explode(';', $value);
                        break;
                    }
                }
            }
        }

        foreach ($headers as $key) {
            if (!empty($key)) {
                $value = $request->getHeaderLine($key);
                $header_message .= strtolower($key) . ':' . $value . "\n";
            }
        }
        return trim($header_message, "\n");
    }

    // @TODO 3.0 Document
    // @TODO 3.0 Interface?
    // @TODO 3.0 This deserves a new class for the auth headers
    public function getAuthorizationHeaders(RequestSignerInterface $requestSigner, RequestInterface $request) {
        // Authorization-Header-Parameters: normalized parameters similar to
        // section 9.1.1 of OAuth 1.0a. The parameters are the id, nonce, realm,
        // and version from the Authorization header. Parameters are sorted by
        // name and separated by '&' with name and value separated by =, percent
        // encoded (urlencoded)
        $header = $request->getHeaderLine('Authorization');

        if (empty($header)) {
          $id = $requestSigner->getId();
          $nonce = $requestSigner->getNonce();
          $realm = $requestSigner->getRealm();
        } else {
            $id = '';
            $id_match = preg_match('/.*id="(.*?)"/', $header, $id_matches);

            $realm = '';
            $realm_match = preg_match('/.*realm="(.*?)"/', $header, $realm_matches);

            $nonce = '';
            $nonce_match = preg_match('/.*nonce="(.*?)"/', $header, $nonce_matches);

            if (!$id_match || !$realm_match || !$nonce_match) {
                throw new Exception\MalformedRequestException('Authorization header requires a realm, id and a nonce.');
            }
            $id = $id_matches[1];
            $realm = rawurldecode($realm_matches[1]);
            $nonce = $nonce_matches[1];
        }

        $auth_message = sprintf('id=%s&nonce=%s&realm=%s&version=2.0', $id, $nonce, rawurlencode($realm));
        return $auth_message;
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

    /**
     * Returns the canonicalized custom headers.
     *
     * @param \Acquia\Hmac\RequestSignerInterface $requestSigner
     * @param \Psr\Http\Message\RequestInterface $request
     *
     * @return string
     */
    protected function getCustomHeaders(RequestSignerInterface $requestSigner, RequestInterface $request)
    {
        $headers = $requestSigner->getCustomHeaders($request);

        $canonicalizedHeaders = array();
        foreach ($headers as $header => $value) {
            $canonicalizedHeaders[] = strtolower($header) . ': ' . $value;
        }

        sort($canonicalizedHeaders);
        return join("\n", $canonicalizedHeaders);
    }
}
