<?php

namespace Acquia\Hmac;

use Acquia\Hmac\Exception\MalformedRequestException;
use Psr\Http\Message\RequestInterface;

class AuthorizationHeader implements AuthorizationHeaderInterface
{
    protected $realm = 'Acquia';
    protected $id;
    protected $nonce;
    protected $version = '2.0';
    protected $signature;
    protected $headers = [];

    /**
     * Initializes the authorization header with the required fields.
     *
     * @param string $realm
     *   The realm/provider.
     * @param string $id
     *   The API key's unique identifier.
     * @param string $nonce
     *   The nonce, a hex-based v1 or v4 UUID.
     * @param string $version
     *   The version of the HTTP HMAC spec.
     * @param string[] $headers
     *   A list of custom headers included in the signature.
     * @param string $signature
     *   The Base64-encoded signature of the request.
     */
    public function __construct($realm, $id, $nonce, $version, array $headers, $signature)
    {
        $this->realm = $realm;
        $this->id = $id;
        $this->nonce = $nonce;
        $this->version = $version;
        $this->headers = $headers;
        $this->signature = $signature;
    }

    /**
     * {@inheritDoc}
     */
    public static function createFromRequest(RequestInterface $request)
    {
        if (!$request->hasHeader('Authorization')) {
            throw new MalformedRequestException('Authorization header is required.', null, 0, $request);
        }

        $header = $request->getHeaderLine('Authorization');

        $id_match = preg_match('/.*id="(.*?)"/', $header, $id_matches);
        $realm_match = preg_match('/.*realm="(.*?)"/', $header, $realm_matches);
        $nonce_match = preg_match('/.*nonce="(.*?)"/', $header, $nonce_matches);
        $version_match = preg_match('/.*version="(.*?)"/', $header, $version_matches);
        $signature_match = preg_match('/.*signature="(.*?)"/', $header, $signature_matches);
        $headers_match = preg_match('/.*headers="(.*?)"/', $header, $headers_matches);

        if (!$id_match || !$realm_match || !$nonce_match || !$version_match || !$signature_match) {
            throw new MalformedRequestException(
                'Authorization header requires a realm, id, version, nonce and a signature.',
                null,
                0,
                $request
            );
        }

        $customHeaders = !empty($headers_matches[1]) ? explode('%3B', $headers_matches[1]) : [];

        return new static(
            rawurldecode($realm_matches[1]),
            $id_matches[1],
            $nonce_matches[1],
            $version_matches[1],
            $customHeaders,
            $signature_matches[1]
        );
    }

    /**
     * {@inheritDoc}
     */
    public function getRealm()
    {
        return $this->realm;
    }

    /**
     * {@inheritDoc}
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * {@inheritDoc}
     */
    public function getNonce()
    {
        return $this->nonce;
    }

    /**
     * {@inheritDoc}
     */
    public function getVersion()
    {
        return $this->version;
    }

    /**
     * {@inheritDoc}
     */
    public function getCustomHeaders()
    {
        return $this->headers;
    }

    /**
     * {@inheritDoc}
     */
    public function getSignature()
    {
        return $this->signature;
    }

    /**
     * {@inheritDoc}
     */
    public function __toString()
    {
        return 'acquia-http-hmac realm="' . rawurlencode($this->realm) . '",'
        . 'id="' . $this->id . '",'
        . 'nonce="' . $this->nonce . '",'
        . 'version="' . $this->version . '",'
        . 'headers="' . implode('%3B', $this->headers) . '",'
        . 'signature="' . $this->signature . '"';
    }
}
