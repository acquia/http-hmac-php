<?php

namespace Acquia\Hmac\Test;

use Acquia\Hmac\AuthorizationHeader;
use GuzzleHttp\Psr7\Request;

/**
 * Tests the AuthorizationHeader class.
 */
class AuthorizationHeaderTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var string
     *   A sample Authorization header.
     */
    protected $header;

    /**
     * {@inheritDoc}
     */
    protected function setUp()
    {
        $this->header = 'acquia-http-hmac headers="X-Custom-Signer1;X-Custom-Signer2",id="e7fe97fa-a0c8-4a42-ab8e-2c26d52df059",nonce="a9938d07-d9f0-480c-b007-f1e956bcd027",realm="CIStore",signature="0duvqeMauat7pTULg3EgcSmBjrorrcRkGKxRDtZEa1c=",version="2.0"';
    }

    /**
     * Ensures the getters work as expected.
     */
    public function testGetters()
    {
        $realm = 'Pipet service';
        $id = 'efdde334-fe7b-11e4-a322-1697f925ec7b';
        $nonce = 'd1954337-5319-4821-8427-115542e08d10';
        $version = '2.0';
        $headers = ['X-Custom-Signer1', 'X-Custom-Signer2'];
        $signature = 'MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc=';

        $authHeader = new AuthorizationHeader($realm, $id, $nonce, $version, $headers, $signature);

        $this->assertEquals($realm, $authHeader->getRealm());
        $this->assertEquals($id, $authHeader->getId());
        $this->assertEquals($nonce, $authHeader->getNonce());
        $this->assertEquals($version, $authHeader->getVersion());
        $this->assertEquals($headers, $authHeader->getCustomHeaders());
        $this->assertEquals($signature, $authHeader->getSignature());
    }

    /**
     * Ensures an authorization header can be created from a request.
     */
    public function testCreateFromRequest()
    {
        $headers = [
            'Authorization' => $this->header,
        ];
        $request = new Request('GET', 'http://example.com', $headers);

        $authHeader = AuthorizationHeader::createFromRequest($request);

        $this->assertEquals((string) $authHeader, 'acquia-http-hmac realm="CIStore",id="e7fe97fa-a0c8-4a42-ab8e-2c26d52df059",nonce="a9938d07-d9f0-480c-b007-f1e956bcd027",version="2.0",headers="X-Custom-Signer1;X-Custom-Signer2",signature="0duvqeMauat7pTULg3EgcSmBjrorrcRkGKxRDtZEa1c="');
    }

    /**
     * Ensures an exception is thrown if a request does not have an Authorization header.
     *
     * @expectedException \Acquia\Hmac\Exception\MalformedRequestException
     */
    public function testCreateFromRequestNoAuthorizationHeader()
    {
        $request = new Request('GET', 'http://example.com');

        AuthorizationHeader::createFromRequest($request);
    }

    /**
     * Ensures an exception is thrown when a required field is missing.
     *
     * @dataProvider requiredFieldsProvider
     * @expectedException \Acquia\Hmac\Exception\MalformedRequestException
     */
    public function testParseAuthorizationHeaderRequiredFields($field)
    {
        $headers = [
            'Authorization' => preg_replace('/' . $field . '=/', '', $this->header),
        ];
        $request = new Request('GET', 'http://example.com', $headers);

        AuthorizationHeader::createFromRequest($request);
    }

    /**
     * Provides a list of required authorization haeder fields.
     */
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
}
