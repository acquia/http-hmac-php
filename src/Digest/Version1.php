<?php

namespace Acquia\Hmac\Digest;

use Acquia\Hmac\Request\RequestInterface;

class Version1 extends DigestAbstract
{
    /**
     * {@inheritDoc}
     */
    protected function getMessage(RequestInterface $request, array $timestampHeaders, array $customHeaders)
    {
        $parts = array(
            $request->getMethod(),
            md5($request->getBody()),
            $this->getContentType($request),
            $this->getTimestamp($request, $timestampHeaders),
            $request->getResource(),
        );

        return join("\n", $parts);
    }
}
