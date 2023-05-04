<?php
declare(strict_types=1);

namespace Serato\Jwt;

use Aws\Sdk as AwsSdk;

interface IToken
{
    /**
     * Get the AWS client
     *
     * @return AwsSdk
     */
    public function getAws(): AwsSdk;

    /**
     * Get the compact JSON notation form of the token
     *
     * @return string
     */
    public function __toString(): string;

    /**
     * Get a claim's value from a token
     *
     * @param string $key   Name of claim
     *
     * @return mixed
     */
    public function getClaim(string $key);

    /**
     * Get a protected header's value from the token
     *
     * @param string $key   Name of header
     *
     * @return mixed
     */
    public function getProtectedHeader(string $key);

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
    ): bool;

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
    ): ?string;
}
