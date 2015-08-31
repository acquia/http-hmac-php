# HTTP HMAC Signer for PHP

[![Build Status](https://travis-ci.org/acquia/http-hmac-php.svg)](https://travis-ci.org/acquia/http-hmac-php)
[![Code Coverage](https://scrutinizer-ci.com/g/acquia/http-hmac-php/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/acquia/http-hmac-php/?branch=master)
[![HHVM Status](http://hhvm.h4cc.de/badge/acquia/http-hmac-php.svg)](http://hhvm.h4cc.de/package/acquia/http-hmac-php)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/acquia/http-hmac-php/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/acquia/http-hmac-php/?branch=master)
[![Latest Stable Version](https://poser.pugx.org/acquia/http-hmac-php/v/stable.svg)](https://packagist.org/packages/acquia/http-hmac-php)
[![License](https://poser.pugx.org/acquia/http-hmac-php/license.svg)](https://packagist.org/packages/acquia/http-hmac-php)

HMAC Request Signer is a PHP library that implements the [HTTP HMAC Spec](https://github.com/acquia/http-hmac-spec)
to sign and verify RESTful Web API requests. It integrates with popular libraries such as
Symfony and Guzzle and can be used on both the server and client.

## Installation

HMAC Request Signer can be installed with [Composer](http://getcomposer.org)
by adding it as a dependency to your project's composer.json file.

```json
{
    "require": {
        "acquia/http-hmac-php": "*"
    }
}
```

Please refer to [Composer's documentation](https://github.com/composer/composer/blob/master/doc/00-intro.md#introduction)
for more detailed installation and usage instructions.

## Usage

Sign an API request sent via Guzzle (<6).

```php

use Acquia\Hmac\Guzzle3\HmacAuthPlugin;
use Acquia\Hmac\RequestSigner;
use Guzzle\Http\Client;

$requestSigner = new RequestSigner();
$plugin = new HmacAuthPlugin($requestSigner, 'apiKeyId', 'secretKey');

$client = new Client('http://example.com');
$client->addSubscriber($plugin);

$client->get('/resource')->send();

```

Sign an API request sent via Guzzle 6.

```php

use Acquia\Hmac\Guzzle6\HmacAuthHandler;
use Acquia\Hmac\RequestSigner;
use GuzzleHttp\Client;

$requestSigner = new RequestSigner();
$stack = HmacAuthHandler::createWithMiddleware($requestSigner, 'apiKeyId', 'secretKey');

$client = new Client(['handler' => $stack]);
$client->get('http://example.com/resource');

```

Authenticate the request in a Symfony-powered app e.g. [Silex](https://github.com/silexphp/Silex).

```php

use Acquia\Hmac\RequestAuthenticator;
use Acquia\Hmac\RequestSigner;
use Acquia\Hmac\Request\Symfony as RequestWrapper;

// $request is a \Symfony\Component\HttpFoundation\Request object.
$requestWrapper = new RequestWrapper($request);

// $keyLoader implements \Acquia\Hmac\KeyLoaderInterface

$authenticator = new RequestAuthenticator(new RequestSigner(), '+15 minutes');
$key = $authenticator->authenticate($requestWrapper, $keyLoader);

```

## Contributing and Development

Submit changes using GitHub's standard [pull request](https://help.github.com/articles/using-pull-requests) workflow.

All code should adhere to the following standards:

* [PSR-1](https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-1-basic-coding-standard.md)
* [PSR-2](https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-2-coding-style-guide.md)
* [PSR-4](https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-4-autoloader.md)

It is recommend to use the [PHP Coding Standards Fixer](https://github.com/fabpot/PHP-CS-Fixer)
tool to ensure that code adheres to the coding standards mentioned above.

Refer to [PHP Project Starter's documentation](https://github.com/cpliakas/php-project-starter#using-apache-ant)
for the Apache Ant targets supported by this project.
