<?php

namespace Acquia\Hmac\Client;

use GuzzleHttp\Command\Guzzle\DescriptionInterface;
use GuzzleHttp\Command\Guzzle\Deserializer;

class AdaptiveResponseDeserializer extends Deserializer
{
    /**
     * {@inheritdoc}
     */
    public function __construct(DescriptionInterface $description, bool $process, $responseLocations = [])
    {
        static $responseLocations;

        if (!$responseLocations) {
            $responseLocations = [
                'adaptivejson' => new AdaptiveJsonLocation(),
            ];
        }
        parent::__construct($description, $process, $responseLocations);
    }
}
