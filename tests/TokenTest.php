<?php
declare(strict_types=1);

namespace Serato\Jwt\Test;

use Serato\Jwt\Test\TokenImplementation\Token;
use \PHPUnit\Framework\TestCase;
use Base64Url\Base64Url;
use Mockery;
use Mockery\MockInterface;
use Mockery\LegacyMockInterface;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;

/**
 * Unit and integration tests for App\Jwt\AbstractToken
 */
class TokenTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * Create a token, convert it to a string then parse the string
     *
     * @group jwt
     */
    public function testValidParse()
    {
        $token = new Token();
        $token->create();

        $newToken = new Token();
        $newToken->createFromJson((string)$token);
        $this->assertEquals((string)$token, (string)$newToken);
    }

    /**
     * Create a token, alter it's payload then parse it but DON'T check the
     * signature. It should parse OK.
     *
     * @group jwt
     */
    public function testPayloadTamperNoSignatureCheck()
    {
        $token = new Token();
        $token->create();

        $tokenParts = explode('.', (string)$token);
        $jsonString = base64_decode($tokenParts[1]);
        $payload = json_decode($jsonString === false ? '' : $jsonString, true);
        $payload['var1'] = 'fiddled_with';

        $jsonString = json_encode($payload);
        $jsonData = $tokenParts[0] . '.' .
            Base64Url::encode($jsonString === false ? '' : $jsonString) . '.' .
            $tokenParts[2];
        
        $newToken = new Token();
        $newToken->createFromJson($jsonData, false);
        $this->assertEquals($newToken->getClaim('var1'), 'fiddled_with');
    }

    /**
     * Create a token, alter it's payload, parse and check the signature.
     *
     * @expectedException \Serato\Jwt\Exception\InvalidSignatureException
     * @group jwt
     */
    public function testPayloadTamperSignatureCheck()
    {
        $token = new Token();
        $token->create();

        $tokenParts = explode('.', (string)$token);

        $jsonString = base64_decode($tokenParts[1]);
        $payload = json_decode($jsonString === false ? '' : $jsonString, true);
        $payload['var1'] = 'fiddled_with';

        $jsonString = json_encode($payload);
        $jsonData = $tokenParts[0] . '.' .
            Base64Url::encode($jsonString === false ? '' : $jsonString) . '.' .
            $tokenParts[2];
        
        $newToken = new Token();
        $newToken->createFromJson($jsonData);
    }

    /**
     * Check claims.
     * 1. All claims valid (should pass without error)
     *
     * @group jwt
     */
    public function testCheckClaimsAllValid()
    {
        $token = new Token();
        $token->create();
        $token->verifyClaims();
        $this->assertTrue(true);
    }

    /**
     * Check claims.
     * 2. Invalid issuer
     *
     * @expectedException \Serato\Jwt\Exception\InvalidIssuerClaimException
     * @group jwt
     */
    public function testCheckClaimsInvalidIssuer()
    {
        $token = new Token();
        $token->create('fake issuer');
        $token->verifyClaims();
    }

    /**
     * Check claims.
     * 3. Invalid expiry date
     *
     * @expectedException \Serato\Jwt\Exception\TokenExpiredException
     * @group jwt
     */
    public function testCheckClaimsTokenExpired()
    {
        $token = new Token();
        $token->create(null, time() - (2 * 60 * 60));
        $token->verifyClaims();
    }

    /**
     * Check claims.
     * 4. Invalid audience
     *
     * @expectedException \Serato\Jwt\Exception\InvalidAudienceClaimException
     * @group jwt
     */
    public function testCheckClaimsInvalidAudience()
    {
        $token = new Token();
        $token->create();
        $token->verifyClaims('nonsense.serato.com');
    }

    /**
     * Check claims.
     * 5. Invalid subject
     *
     * @expectedException \Serato\Jwt\Exception\InvalidSubjectClaimException
     * @group jwt
     */
    public function testCheckClaimsInvalidSubject()
    {
        $token = new Token();
        $token->create();
        $token->verifyClaims(null, 'bung_subject');
    }


    /**
     * Failed check on claims listed in `crit` header
     *
     * @expectedException \Serato\Jwt\Exception\CriticalClaimsVerificationException
     * @group jwt
     */
    public function testFailedCriticalClaimsHeaderCheck()
    {
        $token = new Token();
        $token->create(null, null, ['iat']);
        $token->verifyClaims();
    }

    /**
     * Test setting and fetching custom protected header
     *
     * @group jwt
     */
    public function testCustomProtectedHeaderValue()
    {
        $headers = [
            'protected_header_1' => 'value_1',
            'protected_header_2' => 'value_2'
        ];
        $token = new Token();
        $token->create(null, null, null, $headers);

        $this->assertEquals(
            $token->getProtectedHeader('protected_header_1'),
            $headers['protected_header_1']
        );
        $this->assertEquals(
            $token->getProtectedHeader('protected_header_2'),
            $headers['protected_header_2']
        );
    }

    /**
     * Tests that `setInvalidRefreshTokenIdCacheItem` puts an item into memcache with the expected
     * key
     *
     * @group jwt
     */
    public function testSetInvalidRefreshTokenIdCacheItem()
    {
        $refreshTokenId = '1234';
        $ttl = 600;
        $mockMemcached = Mockery::mock(\Memcached::class);
        $mockMemcached
            ->shouldReceive('add')
            ->withArgs(["r-$refreshTokenId", $refreshTokenId, $ttl])
            ->andReturn(true);
        $set = Token::setInvalidRefreshTokenIdCacheItem($mockMemcached, $refreshTokenId, $ttl);
        $this->assertTrue($set);
    }

    /**
     * Tests that `getInvalidRefreshTokenIdCacheItem` returns null if a refresh token ID where the corresponding
     * cache key does not exist on memcache.
     *
     * @group jwt
     */
    public function testGetInvalidRefreshTokenIdCacheItemWithCacheMiss()
    {
        $refreshTokenId = '1234';
        $mockMemcached = Mockery::mock(\Memcached::class);
        $mockMemcached->shouldReceive('get')->withArgs(['r-1234'])->andReturn(false);
        $cacheItem = Token::getInvalidRefreshTokenIdCacheItem($mockMemcached, $refreshTokenId);
        $this->assertNull($cacheItem);
    }

    /**
     * Tests that `getInvalidRefreshTokenIdCacheItem` returns a cache item if a refresh token ID where the corresponding
     * cache key exists on memcache.
     *
     * @group jwt
     */
    public function testGetInvalidRefreshTokenIdCacheItemWithCacheHit()
    {
        // Test existing refresh token
        $refreshTokenId = '5678';
        $mockMemcached = Mockery::mock(\Memcached::class);
        $mockMemcached->shouldReceive('get')->withArgs(['r-5678'])->andReturn('5678');
        $cacheItem = Token::getInvalidRefreshTokenIdCacheItem($mockMemcached, $refreshTokenId);
        $this->assertNotNull($cacheItem);
        // Cache item is the same as the refresh token ID
        $this->assertEquals('5678', $cacheItem);
    }
}
