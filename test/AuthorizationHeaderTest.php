<?php

namespace Acquia\Hmac\Test;

use Acquia\Hmac\AuthorizationHeader;
use Acquia\Hmac\AuthorizationHeaderBuilder;
use Acquia\Hmac\Exception\MalformedRequestException;
use Acquia\Hmac\Key;
use GuzzleHttp\Psr7\Request;
use PHPUnit\Framework\TestCase;

/**
 * Tests the AuthorizationHeader class.
 */
class AuthorizationHeaderTest extends TestCase
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
        // @codingStandardsIgnoreStart
        $this->header = 'acquia-http-hmac headers="X-Custom-Signer1;X-Custom-Signer2",id="e7fe97fa-a0c8-4a42-ab8e-2c26d52df059",nonce="a9938d07-d9f0-480c-b007-f1e956bcd027",realm="CIStore",signature="0duvqeMauat7pTULg3EgcSmBjrorrcRkGKxRDtZEa1c=",version="2.0"';
        // @codingStandardsIgnoreEnd
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

        $this->assertEquals(
            (string) $authHeader,
            // @codingStandardsIgnoreStart
            'acquia-http-hmac realm="CIStore",id="e7fe97fa-a0c8-4a42-ab8e-2c26d52df059",nonce="a9938d07-d9f0-480c-b007-f1e956bcd027",version="2.0",headers="X-Custom-Signer1;X-Custom-Signer2",signature="0duvqeMauat7pTULg3EgcSmBjrorrcRkGKxRDtZEa1c="'
            // @codingStandardsIgnoreEnd
        );
    }

    /**
     * Ensures an authorization header is created correctly with an incorrectly-cased request method.
     */
    public function testCaseInsensitiveRequestMethod()
    {
        $authId = 'efdde334-fe7b-11e4-a322-1697f925ec7b';
        $authSecret = 'W5PeGMxSItNerkNFqQMfYiJvH14WzVJMy54CPoTAYoI=';
        $authKey = new Key($authId, $authSecret);

        $nonce   = 'd1954337-5319-4821-8427-115542e08d10';

        $headers = [
            'X-Authorization-Timestamp' => '1432075982',
            'Content-Type' => 'application/json',
        ];


        $request1 = new Request('GET', 'http://example.com', $headers);
        $builder1 = new AuthorizationHeaderBuilder($request1, $authKey);
        $builder1->setId($authId);
        $builder1->setNonce($nonce);
        $authHeader1 = $builder1->getAuthorizationHeader();

        // Guzzle requests automatically normalize request methods on set, so
        // we need to manually set the property to an un-normalized method.
        $request2 = clone $request1;
        $refObject = new \ReflectionObject($request2);
        $refProperty = $refObject->getProperty('method');
        $refProperty->setAccessible(true);
        $refProperty->setValue($request2, 'gEt');

        $builder2 = new AuthorizationHeaderBuilder($request2, $authKey);
        $builder2->setId($authId);
        $builder2->setNonce($nonce);
        $authHeader2 = $builder2->getAuthorizationHeader();

        $this->assertEquals((string) $authHeader1, (string) $authHeader2);
    }

    /**
     * Ensures an exception is thrown if a request does not have an Authorization header.
     *
     * @expectedException \Acquia\Hmac\Exception\MalformedRequestException
     * @expectedExceptionMessage Authorization header is required.
     */
    public function testCreateFromRequestNoAuthorizationHeader()
    {
        $request = new Request('GET', 'http://example.com');

        try {
            AuthorizationHeader::createFromRequest($request);
        } catch (MalformedRequestException $e) {
            $this->assertSame($request, $e->getRequest());
            throw $e;
        }
    }

    /**
     * Ensures an exception is thrown when a required field is missing.
     *
     * @param $field
     *   The authorization header field.
     *
     * @dataProvider requiredFieldsProvider
     *
     * @expectedException \Acquia\Hmac\Exception\MalformedRequestException
     * @expectedExceptionMessage Authorization header requires a realm, id, version, nonce and a signature.
     */
    public function testParseAuthorizationHeaderRequiredFields($field)
    {
        $headers = [
            'Authorization' => preg_replace('/' . $field . '=/', '', $this->header),
        ];
        $request = new Request('GET', 'http://example.com', $headers);

        try {
            AuthorizationHeader::createFromRequest($request);
        } catch (MalformedRequestException $e) {
            $this->assertSame($request, $e->getRequest());
            throw $e;
        }
    }

    /**
     * Provides a list of required authorization header fields.
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

    /**
     * Ensures an exception is thrown when a required field is missing.
     *
     * @expectedException \Acquia\Hmac\Exception\MalformedRequestException
     * @expectedExceptionMessage One or more required authorization header fields (ID, nonce, realm, version) are missing.
     */
    public function testAuthorizationHeaderBuilderRequiresFields()
    {
        $key = new Key('e7fe97fa-a0c8-4a42-ab8e-2c26d52df059', 'bXlzZWNyZXRzZWNyZXR0aGluZ3Rva2VlcA==');
        $headers = [
            'X-Authorization-Timestamp' => '1432075982',
            'Content-Type' => 'application/json',
        ];
        $request = new Request('POST', 'http://example.com?test=true', $headers, 'body text');
        $builder = new AuthorizationHeaderBuilder($request, $key);
        $builder->setNonce('a9938d07-d9f0-480c-b007-f1e956bcd027');
        $builder->setVersion('2.0');

        try {
            $builder->getAuthorizationHeader();
        } catch (MalformedRequestException $e) {
            $this->assertSame($request, $e->getRequest());
            throw $e;
        }
    }

    /**
     * Ensures an exception is thrown when the required X-Authorization-Timestamp field is missing.
     *
     * @expectedException \Acquia\Hmac\Exception\MalformedRequestException
     * @expectedExceptionMessage X-Authorization-Timestamp header missing from request.
     */
    public function testAuthorizationHeaderBuilderRequiresTimestamp()
    {
        $key = new Key('e7fe97fa-a0c8-4a42-ab8e-2c26d52df059', 'bXlzZWNyZXRzZWNyZXR0aGluZ3Rva2VlcA==');
        $headers = [
            'Content-Type' => 'application/json',
        ];
        $request = new Request('POST', 'http://example.com?test=true', $headers, 'body text');
        $builder = new AuthorizationHeaderBuilder($request, $key);
        $builder->setId($key->getId());
        $builder->setNonce('a9938d07-d9f0-480c-b007-f1e956bcd027');
        $builder->setVersion('2.0');

        try {
            $builder->getAuthorizationHeader();
        } catch (MalformedRequestException $e) {
            $this->assertSame($request, $e->getRequest());
            throw $e;
        }
    }

    public function testAuthorizationHeaderBuilder()
    {
        $key = new Key('e7fe97fa-a0c8-4a42-ab8e-2c26d52df059', 'bXlzZWNyZXRzZWNyZXR0aGluZ3Rva2VlcA==');
        $headers = [
            'X-Authorization-Timestamp' => '1432075982',
            'Content-Type' => 'application/json',
        ];
        $request = new Request('POST', 'http://example.com?test=true', $headers, 'body text');
        $builder = new AuthorizationHeaderBuilder($request, $key);
        $builder->setId($key->getId());
        $builder->setNonce('a9938d07-d9f0-480c-b007-f1e956bcd027');
        $builder->setVersion('2.0');

        $header = $builder->getAuthorizationHeader();
        $this->assertEquals($header->getId(), $key->getId());
        $this->assertEquals($header->getSignature(), 'f9G/Xu339hw1z2zHTOrHKNv1kWqvYHYI9Nu/phO5dPY=');

        $builder->setSignature('test');
        $header = $builder->getAuthorizationHeader();
        $this->assertEquals($header->getSignature(), 'test');
    }

    /**
     * Ensures an authorization header is created correctly with a non-standard port used in request.
     */
    public function testNonStandardPortInRequest()
    {
        $key = new Key('e7fe97fa-a0c8-4a42-ab8e-2c26d52df059', 'bXlzZWNyZXRzZWNyZXR0aGluZ3Rva2VlcA==');
        $headers = [
            'X-Authorization-Timestamp' => '1432075982',
            'Content-Type' => 'application/json',
        ];
        $request = new Request('POST', 'http://example.com:8080?test=true', $headers, 'body text');
        $builder = new AuthorizationHeaderBuilder($request, $key);
        $builder->setId($key->getId());
        $builder->setNonce('a9938d07-d9f0-480c-b007-f1e956bcd027');
        $builder->setVersion('2.0');

        $header = $builder->getAuthorizationHeader();
        $this->assertEquals($header->getId(), $key->getId());
        $this->assertEquals($header->getSignature(), 'vIJoGnHstwQ+SaBboP4/DlUAqTGscSbCZav7ufh8KqM=');
    }
}
