<?php

namespace Acquia\Hmac\Client;

use Acquia\Hmac\Exception\KeyNotFoundException;
use Acquia\Hmac\Guzzle\HmacAuthMiddleware;
use Acquia\Hmac\Key;
use Acquia\Hmac\KeyLoader;
use Acquia\Hmac\RequestAuthenticator;
use Acquia\Search\Api\AdaptiveResponseDeserializer;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Command\Guzzle\DescriptionInterface;
use GuzzleHttp\Command\Guzzle\GuzzleClient;
use GuzzleHttp\HandlerStack;
use InvalidArgumentException;
use Symfony\Component\HttpFoundation\Request;

/**
 * This client wraps GuzzleClient to make hmac requests to Acquia Services.
 *
 * Individual services must extend this client since the headers for each
 * service is different.
 */
abstract class AcquiaHmacClient extends GuzzleClient {

    /**
     * Human Readable Version of the Api Service.
     *
     * This must be set with setApi in the child class.
     *
     * @var string
     */
    protected $apiName;

    /**
     * Schema Path to the API JSON Description
     *
     * This must be set with setSchemaPath in the child class.
     *
     * @var string
     */
    protected $schemaPath;

    /**
     * API Description.
     *
     * @var \GuzzleHttp\Command\Guzzle\DescriptionInterface
     */
    protected $apiDescription;

    /**
     * Client configuration array.
     *
     * @var array
     */
    protected $clientConfig;

    /**
     * Client HMAC Credentials, ready for injection into into a Handler Stack.
     *
     * @var \Acquia\Hmac\Guzzle\HmacAuthMiddleware
     */
    protected $clientCredentials;

    /**
     * The client constructor accepts an associative array of configuration
     * options:
     *
     * - defaults: Associative array of default command parameters to add to
     *   each command created by the client.
     * - validate: Specify if command input is validated (defaults to true).
     *   Changing this setting after the client has been created will have no
     *   effect.
     * - process: Specify if HTTP responses are parsed (defaults to true).
     *   Changing this setting after the client has been created will have no
     *   effect.
     * - response_locations: Associative array of location types mapping to
     *   ResponseLocationInterface objects.
     *
     * @param array $config
     *   Configuration options
     * @param array $credentials
     *   Authentication credentials for API access. Should include the following
     *   values:
     *     - api_key: a Search API key
     *     - hmac_key: an Acquia HMAC public key
     *     - hmac_secret: an Acquia HMAC private key
     * @param \GuzzleHttp\ClientInterface $client
     *   HTTP client to use.
     * @param \GuzzleHttp\Command\Guzzle\DescriptionInterface $description
     *   Guzzle service description.
     * @param callable $commandToRequestTransformer
     *   Handler used to serializes requests for a given command.
     * @param callable $responseToResultTransformer
     *   Handler used to create response models based on an HTTP response and
     *   a service description.
     * @param \GuzzleHttp\HandlerStack $commandHandlerStack
     *   Middleware stack.
     *
     * @throws \InvalidArgumentException
     *   When $config has empty 'api_key', 'api_secret', or 'base_uri'.
     *
     * @SuppressWarnings(PHPMD.LongVariable) // Long parameter names are from
     *   Guzzle.
     */
    public function __construct(
        array                $config = [],
        array                $credentials = [],
        ClientInterface      $client = NULL,
        DescriptionInterface $description = NULL,
        callable             $commandToRequestTransformer = NULL,
        callable             $responseToResultTransformer = NULL,
        HandlerStack         $commandHandlerStack = NULL
    ) {
        // Set the Client API Name.
        $this->setApiName();
        $this->setClientConfig($config, $credentials, $commandHandlerStack);
        // Build the HTTP client.
        $client = $client ?: new HttpClient($this->getClientConfig());

        // Set the Description Path.
        $this->setSchemaPath();
        $this->setApiDescription($description);

        // Create the API client.
        $process = (!isset($this->getClientConfig()['process']) || $this->getClientConfig()['process'] === TRUE);
        parent::__construct(
            $client,
            $this->getApiDescription(),
            $commandToRequestTransformer,
            $responseToResultTransformer ?: new AdaptiveResponseDeserializer($this->getApiDescription(), $process),
            $commandHandlerStack,
            $this->getClientConfig()
        );
    }

    /**
     * Retrieve API description.
     *
     * @return \GuzzleHttp\Command\Guzzle\DescriptionInterface
     *   API description instance.
     */
    public function getApiDescription() {
        return $this->apiDescription;
    }

    /**
     * Retrieve client configuration.
     *
     * @return array
     *   Client config array.
     */
    protected function getClientConfig() {
        return $this->clientConfig;
    }

    /**
     * Set API description.
     *
     * Each implimenting service must define an API Description, specifically
     * the schema path.
     *
     * Example:
     *  {
     *     $schema_path = 'path/to/json/file.json'
     *     $this->apiDescription = $description ?: new ClientServiceDescription($schema_path);
     *  }
     *
     * @param \GuzzleHttp\Command\Guzzle\DescriptionInterface|null $description
     *   API description instance.
     *
     * @return $this
     */
    private function setApiDescription(DescriptionInterface $description = NULL) {
        $this->apiDescription = $description ?: new ClientServiceDescription($this->schemaPath);
        return $this;
    }

    /**
     * Prepares the API and HMAC credentials for the client.
     *
     * @param $credentials
     *   An array containing the client API and HMAC credentials.
     * @return $this
     */
    protected function setClientCredentials($credentials)
    {
        // Set API Key Headers, if they exist for the service.
        if (isset($credentials['api_key']) && $this->getServiceApiHeader()) {
            $this->clientConfig['headers'][$this->getServiceApiHeader()] = $credentials['service_key'];
        }
        if (isset($credentials['api_key'], $credentials['api_secret'])) {
            $this->clientCredentials = new HmacAuthMiddleware(
                new Key($credentials['api_key'], $credentials['api_secret']),
                $this->getRealm(),
                $this->getServiceApiHeader() ? [$this->getServiceApiHeader()]: null
            );
        }
        return $this;
    }

    /**
     * Set client configuration.
     *
     * @param array $config
     *   Config array.
     * @param array $credentials
     *   Credentials for API access.
     * @param \GuzzleHttp\HandlerStack|null $commandHandlerStack
     *   HandlerStack instance.
     *
     * @return $this
     */
    protected function setClientConfig(
        array $config = [],
        array $credentials = [],
        HandlerStack $commandHandlerStack = null
    ) {
        $this->clientConfig = $config;
        $this->validateClientConfig()
            ->normalizeClientConfig()
            ->setClientCredentials($credentials)
            ->validateClientCredentials()
            ->setClientConfigHandlerStack($commandHandlerStack);
        return $this;
    }

    /**
     * Set the client configuration handler stack.
     *
     * @param \GuzzleHttp\HandlerStack|null $commandHandlerStack
     *   HandlerStack instance.
     *
     * @return $this
     *
     * @SuppressWarnings(PHPMD.StaticAccess) // Allow creating a default
     *   HandlerStack via static access.
     */
    private function setClientConfigHandlerStack(HandlerStack $commandHandlerStack = null)
    {
        $handlerStack = $commandHandlerStack ?? HandlerStack::create();

        if ($this->clientCredentials) {
            $handlerStack->push($this->clientCredentials);
        }
        $this->clientConfig['handler'] = $handlerStack;
        return $this;
    }

    /**
     * Validate client configuration.
     *
     * @return $this
     *
     * @throws \InvalidArgumentException
     *   When $config has empty 'base_uri'.
     */
    private function validateClientConfig()
    {
        // Make certain that we have a base URI.
        if (empty($this->getClientConfig()['base_uri'])) {
            throw new InvalidArgumentException(
                "The $this->apiName client config is missing the base_uri."
            );
        }
        return $this;
    }

    /**
     * Validates the client API and HMAC credentials.
     *
     * @return $this
     *
     * @throws \InvalidArgumentException
     *   When $config has empty 'base_uri'.
     */
    private function validateClientCredentials()
    {
        // Make certain that we have an API key, HMAC key and HMAC secret.
        if (!isset($this->clientCredentials)) {
            throw new InvalidArgumentException(
                "The $this->apiName credential config is missing API and/or HMAC keys."
            );
        }
        return $this;
    }

    /**
     * Normalize client configuration.
     *
     * @return $this
     */
    private function normalizeClientConfig()
    {
        // Ensure the base_uri value ends with a slash so that relative URIs are
        // appended correctly.
        // @see: https://tools.ietf.org/html/rfc3986#section-5.2
        $this->clientConfig['base_uri'] = preg_replace(
            '#([^/])$#',
            '$1/',
            $this->clientConfig['base_uri']
        );
        // Make certain that config headers exist.
        $this->clientConfig['headers'] = $this->clientConfig['headers'] ?? [];
        // Add the User Agent header if it isn't already part of the headers.
        if (empty($this->clientConfig['headers']['User-Agent'])) {
            $this->clientConfig['headers']['User-Agent'] = $this->getUserAgent();
        }
        // Add Content Type header if not set.
        if (empty($this->clientConfig['headers']['Content-Type'])) {
            $this->clientConfig['headers']['Content-Type'] = 'application/json';
        }

        // Allow additional headers to be set by implementing services
        $this->clientConfig['headers'] = array_merge($this->clientConfig['headers'], $this->getCustomHeaders());
        return $this;
    }

    /**
     * Makes a call to get a client response based on the client name.
     *
     * Note, this receives a Symfony request, but uses a PSR7 Request to Auth.
     *
     * @param \Symfony\Component\HttpFoundation\Request $request
     *   Request.
     *
     * @return \Acquia\Hmac\KeyInterface|bool
     *   Authentication Key, FALSE otherwise.
     */
    public function authenticate(Request $request) {
        if (!$this->getClient()) {
            return FALSE;
        }



        $keys = [
            $this->clientCredentials['api_key'] => $this->client->getSettings()->getSecretKey(),
            'Webhook' => $this->client->getSettings()->getSharedSecret(),
        ];
        $keyLoader = new KeyLoader($keys);

        $authenticator = new RequestAuthenticator($keyLoader);

        $http_message_factory = $this->createPsrFactory();
        $psr7_request = $http_message_factory->createRequest($request);

        try {
            return $authenticator->authenticate($psr7_request);
        }
        catch (KeyNotFoundException $exception) {
            $this->loggerFactory
                ->get('acquia_contenthub')
                ->debug('HMAC validation failed. [authorization_header = %authorization_header]', [
                    '%authorization_header' => $request->headers->get('authorization'),
                ]);
        }

        return FALSE;
    }

    /**
     * Retrieve custom headers to append to normalized headers.
     *
     * Service Classes should override this method if they use custom headers.
     *
     * @return array
     */
    public function getCustomHeaders() {
        return [];
    }

    /**
     * Sets and returns the API Name.
     *
     * Implementing classes must set $apiName with this function.
     *
     * @return string
     *   The Human Readable Version of the API implementing this class.
     */
    abstract public function setApiName(): string;

    /**
     * Sets and returns the JSON Schema Path.
     *
     * Implementing classes must set $schemaPath with this function.
     *
     * @return string
     *   The full path to the JSON Schema Description.
     */
    abstract public function setSchemaPath(): string;

    /**
     * Services use different headers to set their API key.
     *
     * @return string
     */
    abstract public function getServiceApiHeader(): string;

    /**
     * Get the service realm
     *
     * @return string
     *   The Service Realm Machine Name.
     */
    abstract public function getRealm(): string;

    /**
     * Get the service user agent for the library.
     *
     * @return string
     */
    abstract public function getUserAgent(): string;
}
