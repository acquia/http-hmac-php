<?php

namespace Acquia\Hmac;

use Psr\Http\Message\RequestInterface;

interface AuthorizationHeaderInterface
{
    /**
     * Creates an authoriation header from a request.
     *
     * @return static
     */
    public static function createFromRequest(RequestInterface $request);

    /**
     * Retrieves the string representation of the authorization header.
     *
     * @return string
     */
    public function __toString();

    /**
     * Retrives the realm field of the authorization header.
     *
     * @return string
     *   The realm/provider.
     */
    public function getRealm();

    /**
     * Retrives the ID field of the authorization header.
     *
     * @return string
     *   The API key's unique identifier.
     */
    public function getId();

    /**
     * Retrives the nonce field of the authorization header.
     *
     * @return string
     *   The nonce.
     */
    public function getNonce();

    /**
     * Retrives the version field of the authorization header.
     *
     * @return string
     *   The version of the HTTP HMAC spec.
     */
    public function getVersion();

    /**
     * Retrives the list of custom headers signed in the authorization header.
     *
     * @return string[]
     *   The list of custom headers.
     */
    public function getCustomHeaders();

    /**
     * Retrieves the signature of the request.
     *
     * @return string
     *   The Base64-encoded signature of the request.
     */
    public function getSignature();
}
