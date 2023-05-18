<?php

namespace Acquia\Hmac\Client;

use GuzzleHttp\Command\Guzzle\Parameter;
use GuzzleHttp\Command\Guzzle\ResponseLocation\JsonLocation;
use GuzzleHttp\Command\Guzzle\ResponseLocation\ResponseLocationInterface;
use GuzzleHttp\Command\ResultInterface;
use GuzzleHttp\Exception\InvalidArgumentException;
use Psr\Http\Message\ResponseInterface;

/**
 * Class AdaptiveJsonLocation
 *
 * While it mostly deals in JSON responses, some APIs appear to deliver a few
 * non-JSON responses from certain endpoints under certain circumstances. For
 * example, Acquia Search "ping" endpoints tend to return XML, while the base
 * Controller Ping endpoint may simply return a string. This class acts as a
 * safety net; catching any exceptions that our parent JsonLocation might throw
 * during the course of a non-JSON response, and presenting the string response
 * from the underlying Guzzle Client.
 *
 * @todo
 *   Abandon this class and fallback to normal model-based deserialization when
 *   we can rely on more consistent, documented response types from Search API.
 */
class AdaptiveJsonLocation extends JsonLocation implements ResponseLocationInterface
{
    /**
     * {@inheritdoc}
     */
    public function __construct($locationName = 'adaptivejson')
    {
        parent::__construct($locationName);
    }

    /**
     * {@inheritdoc}
     */
    public function before(ResultInterface $result, ResponseInterface $response, Parameter $model)
    {
        try {
            return parent::before($result, $response, $model);
        } catch (InvalidArgumentException $e) {
            return $result;
        }
    }

    /**
     * {@inheritdoc}
     */
    public function after(ResultInterface $result, ResponseInterface $response, Parameter $model)
    {
        try {
            // First, check for valid JSON. If we can return that, then great!
            $output = parent::after($result, $response, $model);
            $result['response'] = ($output === $result) ? (string) $response->getBody() : $output;
        } catch (InvalidArgumentException $e) {
            // If the endpoint we're dealing with returns something that isn't
            // valid JSON, pass it on under the "response" key.
            $result['response'] = (string) $response->getBody();
        }
        return $result;
    }
}
