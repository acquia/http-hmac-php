<?php

namespace Acquia\Hmac;

interface AuthorizationHeaderInterface
{
    /**
     * Adds a header name to be used to create the digest.
     *
     * @param string $key
     */
    public function addSignedHeader($key);

    /**
     * Gets all of the header names used to create the digest.
     *
     * @return string
     */
    public function getSignedHeaders();

    /**
     * Gets the realm.
     *
     * @return string
     */
    public function getRealm();

    /**
     * Sets the realm.
     *
     * @param string $realm
     */
    public function setRealm($realm);

    /**
     * Gets the ID.
     *
     * @return string
     */
    public function getId();

    /**
     * Sets the ID.
     *
     * @param string $id
     */
    public function setId($id);

    /**
     * Gets the nonce.
     *
     * @return string
     */
    public function getNonce();
 
    /**
     * Sets the nonce.
     *
     * @param string $nonce
     */
    public function setNonce($nonce);

    /**
     * Gets the version.
     *
     * @return string
     */
    public function getVersion();

    /**
     * Sets the version.
     *
     * @param string $version
     */
    public function setVersion($version);

    /**
     * Gets the signature.
     *
     * @return string
     */
    public function getSignature();

    /**
     * Sets the signature.
     *
     * @param string $signature
     */
    public function setSignature($signature);

    /**
     * Parses the provided authorization header string.
     *
     * This should be a valid Acquia HMAC 2.0 Authorization header. It will
     * populate all of the internal properties of this object.
     *
     * @param string $header
     */
    public function parseAuthorizationHeader($header);

    /**
     * Creates the Acquia HMAC 2.0 Authorization header.
     *
     * This uses the internal properties, so they must first be populated via
     * setters or via ::parseAuthorizationHeader().
     *
     * @return string
     */
    public function createAuthorizationHeader();

    /**
     * Generates a compatible UUID V4 nonce.
     *
     * @return string
     */
    public function generateNonce();

}
