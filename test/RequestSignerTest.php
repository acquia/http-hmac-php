<?php

namespace Acquia\Hmac\Test;

use Acquia\Hmac\RequestSigner;
use GuzzleHttp\Psr7\Request;

// @TODO 3.0 This contains a lot of malformed headers, which are false negatives because they are v1
class RequestSignerTest extends \PHPUnit_Framework_TestCase
{
    protected $auth_id;

    protected $auth_secret;

    protected $generic_headers;

    protected function setUp()
    {
        $this->auth_id = 'efdde334-fe7b-11e4-a322-1697f925ec7b';
        $this->auth_secret = 'W5PeGMxSItNerkNFqQMfYiJvH14WzVJMy54CPoTAYoI=';
        $this->generic_headers = array(
            'Content-Type' => 'text/plain',
            'X-Authorization-Timestamp' => '1432075982',
            'Authorization' => 'acquia-http-hmac realm="Pipet service",'
            . 'id="' . $this->auth_id . '",'
            . 'nonce="d1954337-5319-4821-8427-115542e08d10",'
            . 'version="2.0",'
            . 'headers="",'
            . 'signature="MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc="',
        );
    }

    public function testSetCustomHeaders()
    {
        $headers = array('Custom1', 'Custom2');

        $signer = new RequestSigner();
        $signer->getAuthorizationHeader()->addSignedHeader('Custom1');
        $signer->getAuthorizationHeader()->addSignedHeader('Custom2');

        $headers = array(
            'Custom1' => 'Value1',
            'Custom2' => 'Value2',
            'Custom3' => 'Value3',
        );
        $request = DummyRequest::generate('GET', 'https://example.com', '/test', '', $headers);

        $expected = array('Custom1', 'Custom2');

        $this->assertEquals($expected, $signer->getAuthorizationHeader()->getSignedHeaders($request));
    }

    public function testAddCustomHeader()
    {
        $headers = array('Custom1' => 'Value1');

        $signer = new RequestSigner();
        $signer->getAuthorizationHeader()->addSignedHeader('Custom1');

        $request = DummyRequest::generate('GET', 'https://example.com', '/test', '', $headers);

        $this->assertEquals(array('Custom1'), $signer->getAuthorizationHeader()->getSignedHeaders($request));
    }

    public function testGetContentType()
    {
        $headers = array('Content-Type' => 'text/plain');
        $request = DummyRequest::generate('GET', 'https://example.com', '/test', '', $headers);

        $signer = new RequestSigner();
        $this->assertEquals('text/plain', $signer->getContentType($request));
    }

    /**
     * @expectedException \Acquia\Hmac\Exception\KeyNotFoundException
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
        $headers = $this->generic_headers;
        $headers['Authorization'] = 'BadRealm 1:abcd';
        $request = DummyRequest::generate('GET', 'https://example.com', '/test', '', $headers);

        $signer = new RequestSigner();
        $signer->getSignature($request);
    }

    /**
     * @expectedException \Acquia\Hmac\Exception\KeyNotFoundException
     */
    public function testInvalidTimestampHeader()
    {
        $headers = $this->generic_headers;
        $headers['X-Authorization-Timestamp'] = 'Acquia 2:abcd';
        $request = DummyRequest::generate('GET', 'https://example.com', '/test', '', $headers);

        $signer = new RequestSigner();
        $signer->getSignature($request);
    }

    /**
     * @expectedException \Acquia\Hmac\Exception\KeyNotFoundException
     */
    public function testMissingSignature()
    {
        $headers = array(
            'Content-Type' => 'text/plain',
            'X-Authorization-Timestamp' => '1432075982',
            'Authorization' => 'acquia-http-hmac realm="Pipet service",'
            . 'id="' . $this->auth_id . '",'
            . 'nonce="d1954337-5319-4821-8427-115542e08d10",'
            . 'version="2.0",'
            . 'headers="",'
            . 'signature=""',
        );
        $request = DummyRequest::generate('GET', 'https://example.com', '/test', '', $headers);

        $signer = new RequestSigner();
        $signer->getAuthorizationHeader()->parseAuthorizationHeader($headers['Authorization']);
        $signer->getSignature($request);
    }

    /**
     * @expectedException \Acquia\Hmac\Exception\MalformedRequestException
     */
    public function testInvalidSignature()
    {
        $headers = array(
            'Content-Type' => 'text/plain',
            'X-Authorization-Timestamp' => '1432075982',
            'Authorization' => 'acquia-http-hmac realm="Pipet service",'
            . 'id="' . $this->auth_id . '",'
            . 'nonce="d1954337-5319-4821-8427-115542e08d10",'
            . 'version="2.0",'
            . 'headers="",'
            . 'signature="1===="',
        );
        $request = DummyRequest::generate('GET', 'https://example.com', '/test', '', $headers);

        $signer = new RequestSigner();
        $signer->getAuthorizationHeader()->parseAuthorizationHeader($headers['Authorization']);
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
        $signer->setTimestamp(1432075982);
        $signer->getAuthorizationHeader()->parseAuthorizationHeader($headers['Authorization']);
        $signature = $signer->getSignature($request);

        $this->assertInstanceOf('Acquia\Hmac\Signature', $signature);
        $this->assertEquals($this->auth_id, $signature->getId());
        $this->assertEquals('MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc=', $signature->getSignature());
        $this->assertEquals(1432075982, $signature->getTimestamp());
    }

    public function testSignRequest()
    {
        $signer = new RequestSigner();
        $signer->setTimestamp(1432075982);

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

        $signer->getAuthorizationHeader()->parseAuthorizationHeader($headers['Authorization']);
        $signed_request = $signer->signRequest($request, $this->auth_secret);
        $this->assertContains('signature="MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc="', $signed_request->getHeaderLine('Authorization'));
    }

    public function testGetAuthorization()
    {
        $signer = new RequestSigner();
        $signer->getAuthorizationHeader()->setNonce('d1954337-5319-4821-8427-115542e08d10');
        $signer->setTimestamp('1432075982');

        $headers = array(
            'Content-Type' => 'text/plain',
            'X-Authorization-Timestamp' => '1432075982',
            'Authorization' => 'acquia-http-hmac realm="Pipet service",'
            . 'id="' . $this->auth_id . '",'
            . 'nonce="' . $signer->getAuthorizationHeader()->getNonce() .'",'
            . 'version="2.0",'
            . 'headers="",'
            . 'signature="MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc="',
        );
        $request = DummyRequest::generate('GET', 'https://example.acquiapipet.net', '/v1.0/task-status/133', 'limit=10', $headers);

        $expected = 'acquia-http-hmac realm="Pipet%20service",'
                    . 'id="efdde334-fe7b-11e4-a322-1697f925ec7b",'
                    . 'nonce="' . $signer->getAuthorizationHeader()->getNonce() .'",'
                    . 'version="2.0",'
                    . 'headers="",'
                    . 'signature="MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc="';

        $signer->getAuthorizationHeader()->parseAuthorizationHeader($headers['Authorization']);
        $this->assertEquals($expected, $signer->getAuthorization($request, $this->auth_id, $this->auth_secret));
    }

    public function testAuthorizationHeaderPassThrough()
    {
        // Ensure that our pass-throughs work as expected between the
        // RequestSigner and the AuthorizationHeader.
        $signer = new RequestSigner();

        $test_realm = 'test realm';
        $signer->getAuthorizationHeader()->setRealm($test_realm);
        $this->assertEquals($signer->getAuthorizationHeader()->getRealm(), $test_realm);
        $this->assertEquals($signer->getHeaderRealm(), $test_realm);
        $signer->setHeaderRealm($test_realm);
        $this->assertEquals($signer->getAuthorizationHeader()->getRealm(), $test_realm);
        $this->assertEquals($signer->getHeaderRealm(), $test_realm);

        $test_id = 'efdde334-fe7b-11e4-a322-1697f925ec7b';
        $signer->getAuthorizationHeader()->setId($test_id);
        $this->assertEquals($signer->getAuthorizationHeader()->getId(), $test_id);
        $this->assertEquals($signer->getHeaderId(), $test_id);
        $signer->setHeaderId($test_id);
        $this->assertEquals($signer->getAuthorizationHeader()->getId(), $test_id);
        $this->assertEquals($signer->getHeaderId(), $test_id);

        $test_nonce = 'd1954337-5319-4821-8427-115542e08d10';
        $signer->getAuthorizationHeader()->setNonce($test_nonce);
        $this->assertEquals($signer->getAuthorizationHeader()->getNonce(), $test_nonce);
        $this->assertEquals($signer->getHeaderNonce(), $test_nonce);
        $signer->setHeaderNonce($test_nonce);
        $this->assertEquals($signer->getAuthorizationHeader()->getNonce(), $test_nonce);
        $this->assertEquals($signer->getHeaderNonce(), $test_nonce);

        $test_version = '2.1';
        $signer->getAuthorizationHeader()->setVersion($test_version);
        $this->assertEquals($signer->getAuthorizationHeader()->getVersion(), $test_version);
        $this->assertEquals($signer->getHeaderVersion(), $test_version);
        $signer->setHeaderVersion($test_version);
        $this->assertEquals($signer->getAuthorizationHeader()->getVersion(), $test_version);
        $this->assertEquals($signer->getHeaderVersion(), $test_version);

        $test_signature = 'MRlPr/Z1WQY2sMthcaEqETRMw4gPYXlPcTpaLWS2gcc=';
        $signer->getAuthorizationHeader()->setSignature($test_signature);
        $this->assertEquals($signer->getAuthorizationHeader()->getSignature(), $test_signature);
        $this->assertEquals($signer->getHeaderSignature(), $test_signature);
        $signer->setHeaderSignature($test_signature);
        $this->assertEquals($signer->getAuthorizationHeader()->getSignature(), $test_signature);
        $this->assertEquals($signer->getHeaderSignature(), $test_signature);

        $test_headers = array('one', 'two');
        $signer->addSignedHeader($test_headers[0]);
        $signer->getAuthorizationHeader()->addSignedHeader($test_headers[1]);
        $this->assertEquals($signer->getAuthorizationHeader()->getSignedHeaders(), $test_headers);
        $this->assertEquals($signer->getSignedHeaders(), $test_headers);
    }
}
