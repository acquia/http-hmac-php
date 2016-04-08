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
use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;

$requestSigner = new RequestSigner();
$requestSigner->getAuthorizationHeader()->setId('e7fe97fa-a0c8-4a42-ab8e-2c26d52df059');
$requestSigner->getAuthorizationHeader()->setRealm('CIStore');
$requestSigner->getAuthorizationHeader()->addSignedHeader('X-Custom-1');
$requestSigner->getAuthorizationHeader()->addSignedHeader('X-Custom-2');

// Guzzle middleware will sign the request by generating the required headers.
// You must provide the ID and secret. According to the Acquia HMAC 2.0 spec,
// the ID is an arbitrary string and the secret is a base64 encoded string.
$middleware = new HmacAuthMiddleware($requestSigner, base64_encode('secret'));

$stack = HandlerStack::create();
$stack->push($middleware);

$client = new Client([
    'handler' => $stack,
]);

// Signed headers must be provided if added above. These will be used to
// generate the signature hash.
$options = [
  'headers' => [
    'X-Custom-1' => 'some custom value',
    'X-Custom-2' => 'another custom value',
  ],
];

$client->get('http://example.com/resource', $options);
```

### Authenticate the request using PSR-7-compatible requests

```php
// @TODO 3.0 This needs to be verified.
use Acquia\Hmac\RequestAuthenticator;
use Acquia\Hmac\RequestSigner;

// $request implements PSR-7's \Psr\Http\Message\RequestInterface
$authorization_header = $request->getHeaderLine('Authorization');

$signer = new RequestSigner();
$authenticator = new RequestAuthenticator($signer, '+15 minutes');

// $keyLoader implements \Acquia\Hmac\KeyLoaderInterface
$key = $authenticator->authenticate($request, $keyLoader);

```

To convert a HTTP Foundation request (used in Symfony-powered apps like Silex) to PSR-7, use Symfony's [PSR-7 bridge](http://symfony.com/doc/current/cookbook/psr7.html):
 
```php
// @TODO 3.0 This needs to be verified.
use Acquia\Hmac\RequestAuthenticator;
use Acquia\Hmac\RequestSigner;
use Symfony\Bridge\PsrHttpMessage\Factory\DiactorosFactory

$authenticator = new RequestAuthenticator(new RequestSigner(), '+15 minutes');

// $request is an HTTP Foundation request
$psr7Factory = new DiactorosFactory();
$psr7Request = $psr7Factory->createRequest($request);

// $keyLoader implements \Acquia\Hmac\KeyLoaderInterface
$key = $authenticator->authenticate($psr7Request, $keyLoader);

```
 
## Contributing and Development

Submit changes using GitHub's standard [pull request](https://help.github.com/articles/using-pull-requests) workflow.

All code should adhere to the following standards:

* [PSR-1](https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-1-basic-coding-standard.md)
* [PSR-2](https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-2-coding-style-guide.md)
* [PSR-4](https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-4-autoloader.md)
* [PSR-7](https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-7-http-message.md)

It is recommend to use the [PHP Coding Standards Fixer](https://github.com/fabpot/PHP-CS-Fixer)
tool to ensure that code adheres to the coding standards mentioned above.

Refer to [PHP Project Starter's documentation](https://github.com/cpliakas/php-project-starter#using-apache-ant)
for the Apache Ant targets supported by this project.
