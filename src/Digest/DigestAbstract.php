<?php

namespace Acquia\Hmac\Digest;

use Acquia\Hmac\Exception as Exception;
use Acquia\Hmac\Request\RequestInterface;

abstract class DigestAbstract implements DigestInterface
{
    /**
     * @var string
     */
    protected $algorithm = 'sha1';

    /**
     * @param string $algorithm
     */
    public function setAlgorithm($algorithm)
    {
        $this->algorithm = $algorithm;
        return $this;
    }
    /**
     * @return string
     */
    public function getAlgorithm()
    {
        return $this->algorithm;
    }

    /**
     * {@inheritDoc}
     */
    public function get(RequestInterface $request, $secretKey, array $timestampHeaders, array $customHeaders)
    {
        $message = $this->getMessage($request, $timestampHeaders, $customHeaders);
        $digest = hash_hmac($this->algorithm, $message, $secretKey, true);
        return base64_encode($digest);
    }

    /**
     * Returns the signature.
     *
     * @param Acquia\Hmac\Request\RequestInterface $request
     * @param array $timestampHeaders
     * @param array $customHeaders
     *
     * @return string
     */
    abstract protected function getMessage(RequestInterface $request, array $timestampHeaders, array $customHeaders);

    /**
     * @param \Acquia\Hmac\Request\RequestInterface $request
     * @param array $timestampHeaders
     *
     * @return string
     *
     * @throws \Acquia\Hmac\Exception\MalformedRequestException
     */
    public function getTimestamp(RequestInterface $request, array $timestampHeaders)
    {
        foreach ($timestampHeaders as $header) {
            if ($request->hasHeader($header)) {
                return $request->getHeader($header);
            }
        }

        if (count($timestampHeaders) > 1) {
            $message = 'At least one of the following headers is required: ' . join(', ' . $timestampHeaders);
        } else {
            $message = $timestampHeaders[0] . ' header required';
        }

        throw new Exception\MalformedRequestException($message);
    }

    /**
     * @param \Acquia\Hmac\Request\RequestInterface $request
     *
     * @return string
     *
     * @throws \Acquia\Hmac\Exception\MalformedRequestException
     */
    protected function getContentType(RequestInterface $request)
    {
        if (!$request->hasHeader('Content-Type')) {
            throw new Exception\MalformedRequestException('Content type header required');
        }

        return $request->getHeader('Content-Type');
    }
}
