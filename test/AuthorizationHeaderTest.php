<?php

namespace Acquia\Hmac\Test;

use Acquia\Hmac\AuthorizationHeader;

class AuthorizationHeaderTest extends \PHPUnit_Framework_TestCase
{
    protected $header;

    protected function setUp()
    {
        $this->header = 'acquia-http-hmac headers="X-Custom-Signer1;X-Custom-Signer2",id="e7fe97fa-a0c8-4a42-ab8e-2c26d52df059",nonce="a9938d07-d9f0-480c-b007-f1e956bcd027",realm="CIStore",signature="0duvqeMauat7pTULg3EgcSmBjrorrcRkGKxRDtZEa1c=",version="2.0"';
    }

    public function testParseAuthorizationHeader()
    {
        $auth = new AuthorizationHeader();
        $auth->parseAuthorizationHeader($this->header);

        $this->assertEquals($auth->getSignedHeaders(), ['X-Custom-Signer1', 'X-Custom-Signer2']);
        $this->assertEquals($auth->getId(), 'e7fe97fa-a0c8-4a42-ab8e-2c26d52df059');
        $this->assertEquals($auth->getNonce(), 'a9938d07-d9f0-480c-b007-f1e956bcd027');
        $this->assertEquals($auth->getRealm(), 'CIStore');
        $this->assertEquals($auth->getSignature(), '0duvqeMauat7pTULg3EgcSmBjrorrcRkGKxRDtZEa1c=');
        $this->assertEquals($auth->getVersion(), '2.0');
    }

    public function requiredFieldsProvider()
    {
        return [
          ['id'],
          ['nonce'],
          ['realm'],
          ['signature'],
          ['version'],
        ];
    }

    /**
     * @dataProvider requiredFieldsProvider
     * @expectedException \Acquia\Hmac\Exception\MalformedRequestException
     */
    public function testParseAuthorizationHeaderRequiredFields($field)
    {
        $auth = new AuthorizationHeader();
        $auth->parseAuthorizationHeader(preg_replace('/' . $field . '=/', '', $this->header));
    }

    public function testCreateAuthorizationHeader()
    {
        $auth = new AuthorizationHeader();
        $auth->parseAuthorizationHeader($this->header);
        $header = $auth->createAuthorizationHeader();
        // @TODO 3.0 golang creates the headers="" delimited by %13B which is a
        // url encoded ";". We expect the requests to come through as ";". We
        // should reconcile this behavior.
        $this->assertEquals($header, 'acquia-http-hmac realm="CIStore",id="e7fe97fa-a0c8-4a42-ab8e-2c26d52df059",nonce="a9938d07-d9f0-480c-b007-f1e956bcd027",version="2.0",headers="X-Custom-Signer1;X-Custom-Signer2",signature="0duvqeMauat7pTULg3EgcSmBjrorrcRkGKxRDtZEa1c="');
    }
}
