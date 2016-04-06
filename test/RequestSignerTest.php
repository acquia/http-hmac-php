<?php

namespace Acquia\Hmac\Test;

use Acquia\Hmac\RequestSigner;
use GuzzleHttp\Psr7\Request;

// @TODO 3.0 This contains a lot of malformed headers, which are false negatives because they are v1
class RequestSignerTest extends \PHPUnit_Framework_TestCase
{
    protected $auth_id;

    protected $auth_secret;

    protected function setUp()
    {
        $this->auth_id = 'efdde334-fe7b-11e4-a322-1697f925ec7b';
        $this->auth_secret = 'W5PeGMxSItNerkNFqQMfYiJvH14WzVJMy54CPoTAYoI=';
    }

    public function testSetRealm()
    {
        $signer = new RequestSigner();
        $signer->setRealm('TestRealm');
        $this->assertEquals('TestRealm', $signer->getRealm());
    }

    public function testSetCustomHeaders()
    {
        $headers = array('Custom1', 'Custom2');

        $signer = new RequestSigner();
        $signer->setCustomHeaders(array('Custom1', 'Custom2'));

        $headers = array(
            'Custom1' => 'Value1',
            'Custom2' => 'Value2',
            'Custom3' => 'Value3',
        );
        $request = DummyRequest::generate('GET', 'https://example.com', '/test', '', $headers);

        $expected = array(
            'Custom1' => 'Value1',
            'Custom2' => 'Value2',
        );

        $this->assertEquals($expected, $signer->getCustomHeaders($request));
    }

    public function testAddCustomHeader()
    {
        $headers = array('Custom1' => 'Value1');

        $signer = new RequestSigner();
        $signer->addCustomHeader('Custom1');

        $request = DummyRequest::generate('GET', 'https://example.com', '/test', '', $headers);

        $this->assertEquals($headers, $signer->getCustomHeaders($request));
    }

    public function testGetContentType()
    {
        $headers = array('Content-Type' => 'text/plain');
        $request = DummyRequest::generate('GET', 'https://example.com', '/test', '', $headers);

        $signer = new RequestSigner();
        $this->assertEquals('text/plain', $signer->getContentType($request));
    }

    /**
     * @expectedException \Acquia\Hmac\Exception\MalformedRequestException
     */
    public function testMissingAuthorizationHeader()
    {
        $signer = new RequestSigner();
        $request = DummyRequest::generate();
        $signer->getSignature($request);
    }

    /**
     * @expectedException \Acquia\Hmac\Exception\KeyNotFoundException
     */
    public function testInvalidAuthorizationHeader()
    {
        $headers = array();
        $headers['Authorization'] = 'invalid-header';
        $request = DummyRequest::generate('GET', 'https://example.com', '/test', '', $headers);

        $signer = new RequestSigner();
        $signer->getSignature($request);
    }

    /**
     * @expectedException \Acquia\Hmac\Exception\KeyNotFoundException
     */
    public function testInvalidRealm()
    {
        $headers = array();
        $headers['Authorization'] = 'BadRealm 1:abcd';
        $request = DummyRequest::generate('GET', 'https://example.com', '/test', '', $headers);

        $signer = new RequestSigner();
        $signer->getSignature($request);
    }

    /**
     * @expectedException \Acquia\Hmac\Exception\KeyNotFoundException
     */
    public function testMissingTimestampHeader()
    {
        $headers = array();
        $headers['Authorization'] = 'Acquia 2:abcd';
        $request = DummyRequest::generate('GET', 'https://example.com', '/test', '', $headers);

        $signer = new RequestSigner();
        $signer->getSignature($request);
    }

    /**
     * @expectedException \Acquia\Hmac\Exception\KeyNotFoundException
     */
    public function testInvalidTimestampHeader()
    {
        $headers = array();
        $headers['Authorization'] = 'Acquia 2:abcd';
        $headers['X-Authorization-Timestamp'] = 'Acquia 2:abcd';
        $request = DummyRequest::generate('GET', 'https://example.com', '/test', '', $headers);

        $signer = new RequestSigner();
        $signer->getSignature($request);
    }

    /**
     * @expectedException \Acquia\Hmac\Exception\KeyNotFoundException
     */
    public function testInvalidSignature()
    {
        $headers = array();
        $headers['Authorization'] = 'Acquia 2:abcd';
        $headers['Date'] = 'bad-timestamp';
        $request = DummyRequest::generate('GET', 'https://example.com', '/test', '', $headers);

        $signer = new RequestSigner();
        $signer->getSignature($request);
    }

    public function testSignature()
    {
        $headers = array(
            'Content-Type' => 'text/plain',
            'X-Authorization-Timestamp' => '1432075982',
            'Authorization' => 'acquia-http-hmac realm="Pipet service",'
            . 'id="' . $this->auth_id . '",'
            . 'nonce="d1954337-5319-4821-8427-115542e08d10",'
            . 'version="2.0",'
            . 'headers="",'
            . 'signature="MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc="',
        );
        $request = DummyRequest::generate('GET', 'https://example.com', '/test', '', $headers);

        $signer = new RequestSigner();
        $signature = $signer->getSignature($request);

        $this->assertInstanceOf('Acquia\Hmac\Signature', $signature);
        $this->assertEquals($this->auth_id, $signature->getId());
        $this->assertEquals('MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc=', $signature->getSignature());
        $this->assertEquals(1432075982, $signature->getTimestamp());
    }

    public function testSignRequest()
    {
        $signer = new RequestSigner();

        $headers = array(
            'Content-Type' => 'text/plain',
            'X-Authorization-Timestamp' => '1432075982',
            'Authorization' => 'acquia-http-hmac realm="Pipet service",'
            . 'id="' . $this->auth_id . '",'
            . 'nonce="d1954337-5319-4821-8427-115542e08d10",'
            . 'version="2.0",'
            . 'headers="",'
            . 'signature="MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc="',
        );
        $request = DummyRequest::generate('GET', 'https://example.acquiapipet.net', '/v1.0/task-status/133', 'limit=10', $headers);

        $this->assertEquals("MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc=", $signer->signRequest($request, $this->auth_secret));
    }

    public function testgetAuthorization()
    {
        $signer = new RequestSigner();
        $signer->setNonce('d1954337-5319-4821-8427-115542e08d10');

        $headers = array(
            'Content-Type' => 'text/plain',
            'X-Authorization-Timestamp' => '1432075982',
            'Authorization' => 'acquia-http-hmac realm="Pipet service",'
            . 'id="' . $this->auth_id . '",'
            . 'nonce="' . $signer->getNonce() .'",'
            . 'version="2.0",'
            . 'headers="",'
            . 'signature="MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc="',
        );
        $request = DummyRequest::generate('GET', 'https://example.acquiapipet.net', '/v1.0/task-status/133', 'limit=10', $headers);

        $expected = 'acquia-http-hmac realm="Acquia",'
                    . 'id="efdde334-fe7b-11e4-a322-1697f925ec7b",'
                    . 'nonce="' . $signer->getNonce() .'",'
                    . 'version="2.0",'
                    . 'headers="",'
                    . 'signature="MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc="';

        $this->assertEquals($expected, $signer->getAuthorization($request, $this->auth_id, $this->auth_secret));
    }
}
