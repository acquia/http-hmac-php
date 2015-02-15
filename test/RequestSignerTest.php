<?php

namespace Acquia\Hmac\Test;

use Acquia\Hmac\RequestSigner;

class RequestSignerTest extends \PHPUnit_Framework_TestCase
{
    public function testSetProvider()
    {
        $signer = new RequestSigner();
        $signer->setProvider('TestProvider');
        $this->assertEquals('TestProvider', $signer->getProvider());
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
    public function testMissingContentType()
    {
        $request = new DummyRequest();

        $signer = new RequestSigner();
        $signer->getContentType($request);
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
    public function testInvalidProvider()
    {
        $request = new DummyRequest();
        $request->headers['Authorization'] = 'BadProvider 1:abcd';

        $signer = new RequestSigner();
        $signer->getSignature($request);
    }

    /**
     * @expectedException \Acquia\Hmac\Exception\MalformedRequestException
     */
    public function testMissingTimestampHeader()
    {
        $request = new DummyRequest();
        $request->headers['Authorization'] = 'Acquia 1:abcd';

        $signer = new RequestSigner();
        $signer->getSignature($request);
    }

    /**
     * @expectedException \Acquia\Hmac\Exception\MalformedRequestException
     */
    public function testMissingMultiTimestampHeader()
    {
        $request = new DummyRequest();
        $request->headers['Authorization'] = 'Acquia 1:abcd';

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
        $request->headers['Authorization'] = 'Acquia 1:abcd';
        $request->headers['Date'] = 'bad-timestamp';

        $signer = new RequestSigner();
        $signer->getSignature($request);
    }

    public function testSignature()
    {
        $date = 'Fri, 19 Mar 1982 00:00:04 GMT';

        $request = new DummyRequest();
        $request->headers['Authorization'] = 'Acquia 1:abcd';
        $request->headers['Date1'] = $date;

        $signer = new RequestSigner();
        $signer->setTimestampHeaders(array('Date1'));
        $signature = $signer->getSignature($request);

        $this->assertInstanceOf('Acquia\Hmac\Signature', $signature);
        $this->assertEquals('1', $signature->getId());
        $this->assertEquals('abcd', $signature->getSignature());
        $this->assertEquals(strtotime($date), $signature->getTimestamp());
    }

    public function testSignRequest()
    {
        $signer = new RequestSigner();
        $signer->addCustomHeader('Custom1');

        $request = new DummyRequest();
        $request->headers = array(
            'Content-Type' => 'text/plain',
            'Date' => 'Fri, 19 Mar 1982 00:00:04 GMT',
            'Custom1' => 'Value1',
        );

        $this->assertEquals(DigestVersion1Test::EXPECTED_HASH, $signer->signRequest($request, 'secret-key'));
    }

    public function testgetAuthorization()
    {
        $signer = new RequestSigner();
        $signer->addCustomHeader('Custom1');

        $request = new DummyRequest();
        $request->headers = array(
            'Content-Type' => 'text/plain',
            'Date' => 'Fri, 19 Mar 1982 00:00:04 GMT',
            'Custom1' => 'Value1',
        );

        $expected = 'Acquia 1:' . DigestVersion1Test::EXPECTED_HASH;
        $this->assertEquals($expected, $signer->getAuthorization($request, '1', 'secret-key'));
    }
}
