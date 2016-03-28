<?php

namespace Acquia\Hmac\Test;

use Acquia\Hmac\RequestSigner;

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

        $request = new DummyRequest();
        $request->headers = array(
            'Custom1' => 'Value1',
            'Custom2' => 'Value2',
            'Custom3' => 'Value3',
        );

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

        $request = new DummyRequest();
        $request->headers = $headers;

        $this->assertEquals($headers, $signer->getCustomHeaders($request));
    }

    public function testGetContentType()
    {
        $request = new DummyRequest();
        $request->headers = array('Content-Type' => 'text/plain');

        $signer = new RequestSigner();
        $this->assertEquals('text/plain', $signer->getContentType($request));
    }

    /**
     * @expectedException \Acquia\Hmac\Exception\MalformedRequestException
     */
    public function testMissingAuthorizationHeader()
    {
        $signer = new RequestSigner();
        $signer->getSignature(new DummyRequest());
    }

    /**
     * @expectedException \Acquia\Hmac\Exception\MalformedRequestException
     */
    public function testInvalidAuthorizationHeader()
    {
        $request = new DummyRequest();
        $request->headers['Authorization'] = 'invalid-header';

        $signer = new RequestSigner();
        $signer->getSignature($request);
    }

    /**
     * @expectedException \Acquia\Hmac\Exception\MalformedRequestException
     */
    public function testInvalidRealm()
    {
        $request = new DummyRequest();
        $request->headers['Authorization'] = 'BadRealm 1:abcd';

        $signer = new RequestSigner();
        $signer->getSignature($request);
    }

    /**
     * @expectedException \Acquia\Hmac\Exception\MalformedRequestException
     */
    public function testMissingTimestampHeader()
    {
        $request = new DummyRequest();
        $request->headers['Authorization'] = 'Acquia 2:abcd';

        $signer = new RequestSigner();
        $signer->getSignature($request);
    }

    /**
     * @expectedException \Acquia\Hmac\Exception\MalformedRequestException
     */
    public function testMissingMultiTimestampHeader()
    {
        $request = new DummyRequest();
        $request->headers['Authorization'] = 'Acquia 2:abcd';

        $signer = new RequestSigner();
        $signer->addTimestampHeader('Date2');
        $signer->getSignature($request);
    }

    /**
     * @expectedException \Acquia\Hmac\Exception\MalformedRequestException
     */
    public function testInvalidSignature()
    {
        $request = new DummyRequest();
        $request->headers['Authorization'] = 'Acquia 2:abcd';
        $request->headers['Date'] = 'bad-timestamp';

        $signer = new RequestSigner();
        $signer->getSignature($request);
    }

    public function testSignature()
    {
        $request = new DummyRequest();
        $request->headers = array(
            'Content-Type' => 'text/plain',
            'X-Authorization-Timestamp' => '1432075982',
            'Authorization' => 'acquia-http-hmac realm:"Pipet service",' . "\n"
            . 'id:"' . $this->auth_id . '",' . "\n"
            . 'nonce:"d1954337-5319-4821-8427-115542e08d10",' . "\n"
            . 'version:"2.0",' . "\n"
            . 'headers:"",' . "\n"
            . 'signature:"MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc="',
        );

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
        // @TODO 3.0 add custom headers into the message.
        //$signer->addCustomHeader('Custom1');

        $request = new DummyRequest();
        $request->headers = array(
            'Content-Type' => 'text/plain',
            'X-Authorization-Timestamp' => '1432075982',
            'Authorization' => 'acquia-http-hmac realm:"Pipet service",' . "\n"
            . 'id:"' . $this->auth_id . '",' . "\n"
            . 'nonce:"d1954337-5319-4821-8427-115542e08d10",' . "\n"
            . 'version:"2.0",' . "\n"
            . 'headers:"",' . "\n"
            . 'signature:"MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc="',
        );

        $this->assertEquals("MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc=", $signer->signRequest($request, $this->auth_secret));
    }

    public function testgetAuthorization()
    {
        $signer = new RequestSigner();
        $signer->setNonce('d1954337-5319-4821-8427-115542e08d10');

        $request = new DummyRequest();
        $request->headers = array(
            'Content-Type' => 'text/plain',
            'X-Authorization-Timestamp' => '1432075982',
            'Authorization' => 'acquia-http-hmac realm:"Pipet service",'
            . 'id:"' . $this->auth_id . '",'
            . 'nonce:"' . $signer->getNonce() .'",'
            . 'version:"2.0",'
            . 'headers:"",'
            . 'signature:"MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc="',
        );

        $expected = 'acquia-http-hmac realm="Acquia",'
                    . 'id="efdde334-fe7b-11e4-a322-1697f925ec7b",'
                    . 'nonce="' . $signer->getNonce() .'",'
                    . 'version="2.0",'
                    . 'headers="",'
                    . 'signature="MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc="';

        $this->assertEquals($expected, $signer->getAuthorization($request, $this->auth_id, $this->auth_secret));
    }
}
