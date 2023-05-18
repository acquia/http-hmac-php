<?php

namespace Acquia\Hmac\Client;

use GuzzleHttp\Command\Guzzle\Description;
use Webbj74\JSDL\Loader\ServiceDescriptionLoader;

/**
 * Class ClientServiceDescription.
 */
class ClientServiceDescription extends Description
{

    /**
     * The JSON Schema Path
     */
    protected $schema_path;

    /**
     * Acquia Client Service descriptions.
     *
     * Loads the commands available from a service via JSON file located in the
     * service SDK.
     *
     * @param string $schema_path
     *   The full path to the JDSL JSON schema being loaded.
     *
     * @param array $options
     *   An array of options to use when configuring the service description.
     */
    public function __construct(string $schema_path, array $options = [])
    {
        $this->schema_path = $schema_path;
        $loader = new ServiceDescriptionLoader();
        $description = $loader->load($this->getSchemaPath());
        parent::__construct($description, $options);
    }

    /**
     * Returns the path to the file containing the service description schema.
     *
     * @return string
     *   The path to the service description schema file.
     */
    protected function getSchemaPath(): string
    {
        return $this->schema_path;
    }
}
