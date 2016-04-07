<?php

namespace Acquia\Hmac;

use Psr\Http\Message\RequestInterface;

class RequestSigner implements RequestSignerInterface
{
    /**
     * @var \Acquia\Hmac\Digest\DigestInterface
     */
    protected $digest;

    /**
     * @var string
     */
    protected $realm = 'Acquia';

    /**
     * @var string
     */
    protected $id;

    /**
     * @var string
     */
    protected $nonce;

    /**
     * @var array
     */
    protected $customHeaders = array();

    /**
     * @param \Acquia\Hmac\Digest\DigestInterface $digest
     */
    public function __construct(Digest\DigestInterface $digest = null)
    {
        $this->digest = $digest ?: new Digest\Version2();
    }

    // @TODO 3.0 Interface/test
    public function getId()
    {
        return $this->id;
    }

    // @TODO 3.0 Interface/test
    public function setId($id)
    {
        $this->id = $id;
    }

    /**
     * {@inheritDoc}
     *
     * @throws \Acquia\Hmac\Exception\MalformedRequest
     */
    public function getSignature(RequestInterface $request)
    {
        // @TODO 3.0 better AuthHeader handling, probably new class
        $header = $request->getHeaderLine('Authorization');
        if (!$request->hasHeader('Authorization')) {
            throw new Exception\MalformedRequestException('Authorization header required');
        }

        $id = '';
        $id_match = preg_match('/.*id="(.*?)"/', $header, $id_matches);

        $signature = '';
        $signature_match = preg_match('/.*signature="(.*?)"/', $header, $signature_matches);

        if (!$id_match) {
            throw new Exception\KeyNotFoundException('Authorization header requires an id.');
        }

        if (!$signature_match) {
            throw new Exception\KeyNotFoundException('Authorization header requires a signature.');
        }

        $id = $id_matches[1];
        $signature = $signature_matches[1];

        // Ensure the signature is a base64 encoded string.
        if (!preg_match('@^[a-zA-Z0-9+/]+={0,2}$@', $signature)) {
            throw new Exception\MalformedRequestException('Invalid signature in authorization header');
        }

        $timestamp = $this->getTimestamp($request);
        if (!$timestamp || !is_numeric($timestamp) || (int) $timestamp < 0 || (int) $timestamp > time()) {
            throw new Exception\MalformedRequestException('Timestamp not valid');
        }

        return new Signature(stripslashes($id), $signature, $timestamp);
    }

    /**
     * {@inheritDoc}
     *
     * @throws \InvalidArgumentException
     * @throws \Acquia\Hmac\Exception\InvalidRequestException
     */
    public function signRequest(RequestInterface $request, $secretKey)
    {
        return $this->digest->get($this, $request, $secretKey);
    }

    // @TODO 3.0 Interface
    // @TODO 3.0 Test
    public function getHashedBody(RequestInterface $request) {
        $hash = '';
        if (!empty((string) $request->getBody())) { 
            $hash = $this->digest->getHashedBody($request);
        }
        return $hash;
    }

    /**
     * {@inheritDoc}
     *
     * @throws \Acquia\Hmac\Exception\InvalidRequestException
     */
    public function getAuthorization(RequestInterface $request, $id, $secretKey, $nonce = null)
    {
        // @TODO 3.0 New Authorization header format:
        // realm: The provider, for example "Acquia", "MyCompany", etc.
        // id: The API key's unique identifier, which is an arbitrary string
        // nonce: a hex version 4 (or version 1) UUID.
        // version: the version of this spec
        // headers: a list of additional request headers that are to be included in the signature base string. These are lower-case, and separated with ;
        // signature: the Signature (base64 encoded) as described below.
        // Each value should be enclosed in double quotes and urlencoded (percent encoded).

        $this->setId($id);

        // e.g. Authorization: acquia-http-hmac realm="Pipet%20service",
        // @TODO 3.0 supply the headers.
        if (!empty($nonce)) {
          $this->setNonce($nonce);
        } elseif (empty($this->getNonce())) {
          $this->setNonce($this->generateNonce());
        }
        $nonce = $this->getNonce();

        $signed_headers = implode(';', array_keys($this->getCustomHeaders($request)));
        return 'acquia-http-hmac realm="' . rawurlencode($this->realm) . '",'
        . 'id="' . $id . '",'
        . 'nonce="' . $nonce . '",'
        . 'version="2.0",'
        . 'headers="' . $signed_headers . '",'
        . 'signature="' . $this->signRequest($request, $secretKey) . '"';
    }

    /**
     * @param string $realm
     *
     * @return \Acquia\Hmac\RequestSigner
     */
    public function setRealm($realm)
    {
        $this->realm = $realm;
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function getRealm()
    {
        return $this->realm;
    }

    // @TODO 3.0 Interface
    // @TODO Test
    public function setNonce($nonce)
    {
        $this->nonce = $nonce;
    }

    // @TODO 3.0 Interface
    // @TODO Test
    public function getNonce()
    {
        return $this->nonce;
    }

    /**
     * Append a custom headers to be used in the signature.
     *
     * @param string $header
     *
     * @return \Acquia\Hmac\RequestSigner
     */
    public function addCustomHeader($header)
    {
        $this->customHeaders[] = $header;
        return $this;
    }

    /**
     * @param array $headers
     *
     * @return \Acquia\Hmac\RequestSigner
     */
    public function setCustomHeaders(array $headers)
    {
        $this->customHeaders = $headers;
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function getContentType(RequestInterface $request)
    {
        return $request->getHeaderLine('Content-Type');
    }

    /**
     * {@inheritDoc}
     */
    public function getTimestamp(RequestInterface $request)
    {
        $timestamp = $request->getHeaderLine('X-Authorization-Timestamp');

        if (empty($timestamp)) {
            throw new Exception\MalformedRequestException('X-Authorization-Timestamp is required');
        }

        return $timestamp;
    }

    /**
     * {@inheritDoc}
     */
    public function getCustomHeaders(RequestInterface $request)
    {
        $headers = array();
        foreach ($this->customHeaders as $header) {
            if ($request->hasHeader($header)) {
                $headers[$header] = $request->getHeaderLine($header);
            }
        }
        return $headers;
    }

    // @TODO 3.0 interface/test
    public function generateNonce() {
        return sprintf( '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            // 32 bits for "time_low"
            mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff ),

            // 16 bits for "time_mid"
            mt_rand( 0, 0xffff ),

            // 16 bits for "time_hi_and_version",
            // four most significant bits holds version number 4
            mt_rand( 0, 0x0fff ) | 0x4000,

            // 16 bits, 8 bits for "clk_seq_hi_res",
            // 8 bits for "clk_seq_low",
            // two most significant bits holds zero and one for variant DCE1.1
            mt_rand( 0, 0x3fff ) | 0x8000,

            // 48 bits for "node"
            mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff )
        );
    }
}
