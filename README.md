# HTTP HMAC Signer for PHP

[![Build Status](https://travis-ci.org/acquia/http-hmac-php.svg)](https://travis-ci.org/acquia/http-hmac-php)
[![Code Coverage](https://scrutinizer-ci.com/g/acquia/http-hmac-php/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/acquia/http-hmac-php/?branch=master)
[![HHVM Status](http://hhvm.h4cc.de/badge/acquia/http-hmac-php.svg?style=flat)](http://hhvm.h4cc.de/package/acquia/http-hmac-php)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/acquia/http-hmac-php/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/acquia/http-hmac-php/?branch=master)
[![Total Downloads](https://poser.pugx.org/acquia/http-hmac-php/downloads)](https://packagist.org/packages/acquia/http-hmac-php)
[![Latest Stable Version](https://poser.pugx.org/acquia/http-hmac-php/v/stable.svg)](https://packagist.org/packages/acquia/http-hmac-php)
[![License](https://poser.pugx.org/acquia/http-hmac-php/license.svg)](https://packagist.org/packages/acquia/http-hmac-php)

HMAC Request Signer is a PHP library that implements the version 2.0 of the [HTTP HMAC Spec](https://github.com/acquia/http-hmac-spec/tree/2.0)
to sign and verify RESTful Web API requests. It integrates with popular libraries such as
Symfony and Guzzle and can be used on both the server and client.

## Installation

HMAC Request Signer can be installed with [Composer](http://getcomposer.org)
by adding it as a dependency to your project's composer.json file.

```json
{
    "require": {
        "acquia/http-hmac-php": "~3.0.0"
    }
}
```

Please refer to [Composer's documentation](https://github.com/composer/composer/blob/master/doc/00-intro.md#introduction)
for more detailed installation and usage instructions.

## Usage

### Sign an API request sent via Guzzle

```php

use Acquia\Hmac\Guzzle\HmacAuthMiddleware;
use Acquia\Hmac\RequestSigner;
use Acquia\Hmac\AuthorizationHeaderBuilder;
use Acquia\Hmac\Digest\Digest;
use Acquia\Hmac\Key;
use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;

// Optionally, you can provide signed headers to generate the digest. The header keys need to be provided to the middleware below.
$options = [
  'headers' => [
    'X-Custom-1' => 'value1',
    'X-Custom-2' => 'value2',
  ],
];

// A key consists of your UUID and a MIME base64 encoded shared secret.
$key = new Key('e7fe97fa-a0c8-4a42-ab8e-2c26d52df059', base64_encode('secret'));

// Provide your key, realm and optional signed headers.
$middleware = new HmacAuthMiddleware($key, 'CIStore', array_keys($options['headers']));

// Register the middleware.
$stack = HandlerStack::create();
$stack->push($middleware);

// Create a client.
$client = new Client([
    'handler' => $stack,
]);

// Request.
$result = $client->get('https://service.acquia.io/api/v1/widget', $options);
var_dump($result);
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

$signer = new ResponseSigner($key, $request)
$signedResponse = $signer->signResponse($response);
```

To convert a HTTP Foundation request (used in Symfony-powered apps like Silex) to PSR-7, use Symfony's [PSR-7 bridge](http://symfony.com/doc/current/cookbook/psr7.html):

```php
use Acquia\Hmac\RequestAuthenticator;
use Acquia\Hmac\RequestSigner;
use Symfony\Bridge\PsrHttpMessage\Factory\DiactorosFactory

// $keyLoader implements \Acquia\Hmac\KeyLoaderInterface
$authenticator = new RequestAuthenticator($keyLoader);

// $request is an HTTP Foundation request
$psr7Factory = new DiactorosFactory();
$psr7Request = $psr7Factory->createRequest($request);

// $keyLoader implements \Acquia\Hmac\KeyLoaderInterface
$key = $authenticator->authenticate($psr7Request);
```

## Contributing and Development

Submit changes using GitHub's standard [pull request](https://help.github.com/articles/using-pull-requests) workflow.

All code should adhere to the following standards:

* [PSR-1](https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-1-basic-coding-standard.md)
* [PSR-2](https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-2-coding-style-guide.md)
* [PSR-4](https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-4-autoloader.md)
* [PSR-7](https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-7-http-message.md)

Use [PHP_CodeSniffer](https://github.com/squizlabs/php_codesniffer) to validate coding style and automatically fix problems according to the PSR-2 standard:
```
$ vendor/bin/phpcs --standard=PSR2 --runtime-set ignore_warnings_on_exit true --colors src/.
$ vendor/bin/phpcs --standard=PSR2 --runtime-set ignore_warnings_on_exit true --colors test/.
$ vendor/bin/phpcbf --standard=PSR2 src/.
$ vendor/bin/phpcbf --standard=PSR2 test/.
```

Refer to [PHP Project Starter's documentation](https://github.com/cpliakas/php-project-starter#using-apache-ant)
for the Apache Ant targets supported by this project.
