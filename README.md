# HTTP HMAC Signer for PHP

[![Build Status](https://travis-ci.org/acquia/http-hmac-php.svg)](https://travis-ci.org/acquia/http-hmac-php)
[![Total Downloads](https://poser.pugx.org/acquia/http-hmac-php/downloads)](https://packagist.org/packages/acquia/http-hmac-php)
[![Latest Stable Version](https://poser.pugx.org/acquia/http-hmac-php/v/stable.svg)](https://packagist.org/packages/acquia/http-hmac-php)
[![License](https://poser.pugx.org/acquia/http-hmac-php/license.svg)](https://packagist.org/packages/acquia/http-hmac-php)

This library implements version 2.0 of the [HTTP HMAC Spec](https://github.com/acquia/http-hmac-spec/tree/2.0) to sign and verify RESTful Web API requests. It integrates with popular frameworks and libraries, like Symfony and Guzzle, and can be used on both the server and client.

## Installation

Use [Composer](http://getcomposer.org) and add it as a dependency to your project's composer.json file:

```json
{
    "require": {
        "acquia/http-hmac-php": "^5.0"
    }
}
```

Please refer to [Composer's documentation](https://github.com/composer/composer/blob/master/doc/00-intro.md#introduction) for more detailed installation and usage instructions.

## Usage

### Sign an API request sent via Guzzle

```php

require_once 'vendor/autoload.php';

use Acquia\Hmac\Guzzle\HmacAuthMiddleware;
use Acquia\Hmac\Key;
use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;

// Create the HTTP HMAC key.
// A key consists of and ID and a Base64-encoded shared secret.
// Note: the API provider may have already encoded the secret. In this case, it should not be re-encoded.
$key_id = 'e7fe97fa-a0c8-4a42-ab8e-2c26d52df059';
$key_secret = base64_encode('secret');
$key = new Key($key_id, $key_secret);

// Optionally, you can provide additional headers when generating the signature.
// The header keys need to be provided to the middleware below.
$headers = [
    'X-Custom-1' => 'value1',
    'X-Custom-2' => 'value2',
];

// Specify the API's realm.
// Consult the API documentation for this value.
$realm = 'Acquia';

// Create a Guzzle middleware to handle authentication during all requests.
// Provide your key, realm and the names of any additional custom headers.
$middleware = new HmacAuthMiddleware($key, $realm, array_keys($headers));

// Register the middleware.
$stack = HandlerStack::create();
$stack->push($middleware);

// Create a client.
$client = new Client([
    'handler' => $stack,
]);

// Request.
try {
    $result = $client->get('https://service.acquia.io/api/v1/widget', [
        'headers' => $headers,
    ]);
} catch (ClientException $e) {
    print $e->getMessage();
    $response = $e->getResponse();
}
  
print $response->getBody();
```

### Authenticate the request using PSR-7-compatible requests

```php
use Acquia\Hmac\RequestAuthenticator;
use Acquia\Hmac\ResponseSigner;

// $keyLoader implements \Acquia\Hmac\KeyLoaderInterface
$authenticator = new RequestAuthenticator($keyLoader);

// $request implements PSR-7's \Psr\Http\Message\RequestInterface
// An exception will be thrown if it cannot authenticate.
$key = $authenticator->authenticate($request);

$signer = new ResponseSigner($key, $request);
$signedResponse = $signer->signResponse($response);
```

### Authenticate using Symfony's Security component

In order to use the provided Symfony integration, you will need to include the following optional libraries in your project's `composer.json`

```json
{
    "require": {
        "symfony/psr-http-message-bridge": "~0.1",
        "symfony/security": "~3.0",
        "zendframework/zend-diactoros": "~1.3.5"
    }
}
```

Sample implementation:

```yaml
# app/config/parameters.yml
parameters:
   hmac_keys: {"key": "secret"}

# app/config/services.yml
services:
    hmac.keyloader:
        class: Acquia\Hmac\KeyLoader
        arguments:
            $keys: '%hmac_keys%'

    hmac.request.authenticator:
        class: Acquia\Hmac\RequestAuthenticator
        arguments:
         - '@hmac.keyloader'
        public: false
        
    hmac.response.signer:
        class: Acquia\Hmac\Symfony\HmacResponseListener
        tags:
          - { name: kernel.event_listener, event: kernel.response, method: onKernelResponse }
          
    hmac.entry-point:
        class: Acquia\Hmac\Symfony\HmacAuthenticationEntryPoint

    hmac.security.authentication.provider:
        class: Acquia\Hmac\Symfony\HmacAuthenticationProvider
        arguments:
            - '@hmac.request.authenticator'
        public: false

    hmac.security.authentication.listener:
        class: Acquia\Hmac\Symfony\HmacAuthenticationListener
        arguments: ['@security.token_storage', '@security.authentication.manager', '@hmac.entry-point']
        public: false

# app/config/security.yml
security:
    # ...

    firewalls:
        hmac_auth:
            pattern:   ^/api/
            stateless: true
            hmac_auth: true
```

```php
// src/AppBundle/AppBundle.php
namespace AppBundle;

use Acquia\Hmac\Symfony\HmacFactory;
use Symfony\Component\HttpKernel\Bundle\Bundle;
use Symfony\Component\DependencyInjection\ContainerBuilder;

class AppBundle extends Bundle
{
    public function build(ContainerBuilder $container)
    {
        parent::build($container);
        $extension = $container->getExtension('security');
        $extension->addSecurityListenerFactory(new HmacFactory());
    }
}
```

PHPUnit testing a controller using HMAC HTTP authentication in Symfony:

1. Add the service declaration:

```yaml
# app/config/parameters_test.yml

services:
    test.client.hmac:
        class: Acquia\Hmac\Test\Mocks\Symfony\HmacClient
        arguments: ['@kernel', '%test.client.parameters%', '@test.client.history', '@test.client.cookiejar']

```

```php
// src/AppBundle/Tests/HmacTestCase.php

namespace MyApp\Bundle\AppBundle\Tests;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Bundle\FrameworkBundle\Client;
use Acquia\Hmac\Key;

class HmacTestCase extends WebTestCase
{
    /**
     * @var Client
     */
    private $client;

    protected static function createClient(array $options = array(), array $server = array())
    {
        $kernel = static::bootKernel($options);

        $client = $kernel->getContainer()->get('test.client.hmac');
        $client->setServerParameters($server);

        return $client;
    }

    protected function setUp()
    {
        $this->client = static::createClient();

        $this->client->setKey(new Key('my-key', 'my-not-really-secret'));
    }
```

## Contributing and Development

[GNU Make](https://www.gnu.org/software/make/) and [Composer](https://getcomposer.org) are used to manage development dependencies and testing:

```sh
# Install depdendencies
make install

# Run test suite
make test
```
 
All code should adhere to the following standards:

* [PSR-1](https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-1-basic-coding-standard.md)
* [PSR-2](https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-2-coding-style-guide.md)
* [PSR-4](https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-4-autoloader.md)
* [PSR-7](https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-7-http-message.md)

Submit changes using GitHub's standard [pull request](https://help.github.com/articles/using-pull-requests) workflow.
