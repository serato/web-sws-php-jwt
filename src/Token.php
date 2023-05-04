<?php
declare(strict_types=1);

namespace Serato\Jwt;

use Aws\Sdk as AwsSdk;

/**
 * Base class for creating and validating JSON Web Signatures (JWS).
 */
abstract class Token
{
    /**
     * The value of the `iat` reserved claim within the JWT token
     */
    protected const ISSUED_BY = 'id.serato.io';

    /** @var AwsSdk */
    private $aws;

    /**
     * Constructs the class
     *
     * @param AwsSdk  $aws AWS client
     * @return void
     */
    public function __construct(AwsSdk $aws)
    {
        $this->aws = $aws;
    }

    /**
     * Get the AWS client
     *
     * @return AwsSdk
     */
    public function getAws(): AwsSdk
    {
        return $this->aws;
    }

    /**
     * Gets a cache key for the given refresh token ID
     *
     * @param string $refreshTokenId Refresh token ID
     * @return string
     */
    private static function getRefreshTokenIdCacheKey(string $refreshTokenId): string
    {
        return 'r-' .  $refreshTokenId;
    }

    /**
     * Writes a refresh token ID into the given memcache connection with a time to live value.
     * The refresh token is considered invalidated when placed into memcache.
     *
     * @param \Memcached $memcache Memcache connection
     * @param string $refreshTokenId Refresh token ID
     * @param integer $ttl Expiry time in seconds
     * @return boolean
     */
    public static function setInvalidRefreshTokenIdCacheItem(
        \Memcached $memcache,
        string $refreshTokenId,
        int $ttl
    ): bool {
    
        return $memcache->add(self::getRefreshTokenIdCacheKey($refreshTokenId), $refreshTokenId, $ttl);
    }

    /**
     * Reads an invalidated refresh token ID from the given memcached connection. Returns null if it doesn't exist.
     *
     * @param \Memcached $memcache Memcache connection
     * @param string $refreshTokenId Refresh token ID
     * @return string|null
     */
    public static function getInvalidRefreshTokenIdCacheItem(
        \Memcached $memcache,
        string $refreshTokenId
    ): ?string {
    
        $cacheItem = $memcache->get(self::getRefreshTokenIdCacheKey($refreshTokenId));
        if ($cacheItem === false) {
            return null;
        }
        return $cacheItem;
    }
}
