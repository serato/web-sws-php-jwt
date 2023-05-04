<?php
declare(strict_types=1);

namespace Serato\Jwt\Test;

use Serato\Jwt\Token;
use \PHPUnit\Framework\TestCase;
use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;

/**
 * Unit and integration tests for App\Jwt\AbstractToken
 */
class TokenTest extends TestCase
{
    use MockeryPHPUnitIntegration;

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
