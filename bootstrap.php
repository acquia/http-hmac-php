<?php

require 'vendor/autoload.php';

use Acquia\Hmac\Guzzle3\HmacAuthPlugin;
use Acquia\Hmac\RequestSigner;
use Guzzle\Http\Client;

$id        = 'aOoDjaFktaAAaPVtgmmT';
$secretKey = '5Jy8KlxdNLHYAw2ALf4Whea4pVxgXLbSkahuBSO8';

$client = new Client('http://localhost:8000');
$client->addSubscriber(new HmacAuthPlugin(new RequestSigner(), $id, $secretKey));

$request = $client->get('/?XDEBUG_SESSION_START=netbeans-xdebug');

$response = $request->send();
echo $response->getStatusCode() . "\n";
