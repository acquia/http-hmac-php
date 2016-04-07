<?php

namespace Acquia\Hmac;

class AuthorizationHeader implements AuthorizationHeaderInterface
{

    protected $realm = 'Acquia';
    protected $id;
    protected $nonce;
    protected $version = '2.0';
    protected $signature;
    protected $headers = [];

    /**
     * {inheritDoc}
     */
    public function addSignedHeader($key) {
        $this->headers[] = $key;
    }

    // @TODO 3.0 test
    /**
     * {inheritDoc}
     */
    public function getSignedHeaders() {
        return $this->headers;
    }

    // @TODO 3.0 test
    /**
     * {inheritDoc}
     */
    public function getRealm()
    {
        return $this->realm;
    }

    // @TODO 3.0 test
    /**
     * {inheritDoc}
     */
    public function setRealm($realm)
    {
        $this->realm = $realm;
    }

    // @TODO 3.0 test
    /**
     * {inheritDoc}
     */
    public function getId()
    {
        return $this->id;
    }

    // @TODO 3.0 test
    /**
     * {inheritDoc}
     */
    public function setId($id)
    {
        $this->id = $id;
    }

    // @TODO 3.0 test
    /**
     * {inheritDoc}
     */
    public function getNonce()
    {
        if (empty($this->nonce)) {
            $this->setNonce($this->generateNonce());
        }

        return $this->nonce;
    }

    // @TODO 3.0 test
    /**
     * {inheritDoc}
     */
    public function setNonce($nonce)
    {
        $this->nonce = $nonce;
    }

    // @TODO 3.0 test
    /**
     * {inheritDoc}
     */
    public function getVersion()
    {
        return $this->version;
    }

    // @TODO 3.0 test
    /**
     * {inheritDoc}
     */
    public function setVersion($version)
    {
        $this->version = $version;
    }

    // @TODO 3.0 test
    /**
     * {inheritDoc}
     */
    public function getSignature()
    {
        return $this->signature;
    }

    // @TODO 3.0 test
    /**
     * {inheritDoc}
     */
    public function setSignature($signature)
    {
        $this->signature = $signature;
    }

    // @TODO 3.0 test
    /**
     * {inheritDoc}
     */
    public function parseAuthorizationHeader($header)
    {
        $id = '';
        $id_match = preg_match('/.*id="(.*?)"/', $header, $id_matches);

        $realm = '';
        $realm_match = preg_match('/.*realm="(.*?)"/', $header, $realm_matches);

        $nonce = '';
        $nonce_match = preg_match('/.*nonce="(.*?)"/', $header, $nonce_matches);

        $version = '';
        $version_match = preg_match('/.*version="(.*?)"/', $header, $version_matches);

        $signature = '';
        $signature_match = preg_match('/.*signature="(.*?)"/', $header, $signature_matches);

        $headers = '';
        $headers_match = preg_match('/.*headers="(.*?)"/', $header, $headers_matches);

        if (!$id_match || !$realm_match || !$nonce_match || !$version_match || !$signature_match) {
            throw new Exception\MalformedRequestException('Authorization header requires a realm, id, version, nonce and a signature.');
        }
        $this->setId($id_matches[1]);
        $this->setRealm(rawurldecode($realm_matches[1]));
        $this->setNonce($nonce_matches[1]);
        $this->setVersion($version_matches[1]);
        $this->setSignature($signature_matches[1]);
        if (!empty($headers_matches[1])) {
            foreach (explode(';', $headers_matches[1]) as $signed_header) {
                $this->addSignedHeader($signed_header);
            }
        }
    }

    public function createAuthorizationHeader()
    {
        $signed_headers = implode(';', $this->getSignedHeaders());
        return 'acquia-http-hmac realm="' . rawurlencode($this->realm) . '",'
        . 'id="' . $this->getId() . '",'
        . 'nonce="' . $this->getNonce() . '",'
        . 'version="' . $this->getVersion() . '",'
        . 'headers="' . $signed_headers . '",'
        . 'signature="' . $this->getSignature() . '"';

    }

    // @TODO 3.0 test
    /**
     * {inheritDoc}
     */
    public function generateNonce()
    {
        return sprintf(
            '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            // 32 bits for "time_low"
            mt_rand(0, 0xffff),
            mt_rand(0, 0xffff),
            // 16 bits for "time_mid"
            mt_rand(0, 0xffff),
            // 16 bits for "time_hi_and_version",
            // four most significant bits holds version number 4
            mt_rand(0, 0x0fff) | 0x4000,
            // 16 bits, 8 bits for "clk_seq_hi_res",
            // 8 bits for "clk_seq_low",
            // two most significant bits holds zero and one for variant DCE1.1
            mt_rand(0, 0x3fff) | 0x8000,
            // 48 bits for "node"
            mt_rand(0, 0xffff),
            mt_rand(0, 0xffff),
            mt_rand(0, 0xffff)
        );
    }

}
