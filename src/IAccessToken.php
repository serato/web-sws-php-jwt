<?php
declare(strict_types=1);

namespace Serato\Jwt;

use Psr\Cache\CacheItemPoolInterface;
use Serato\Jwt\Exception\InvalidAudienceClaimException;
use Serato\Jwt\Exception\InvalidSubjectClaimException;
use Serato\Jwt\Exception\InvalidIssuerClaimException;
use Serato\Jwt\Exception\CriticalClaimsVerificationException;
use Serato\Jwt\Exception\UnhandledTokenCheckException;

interface IAccessToken extends IToken
{
    /**
     * Creates a JWS access token
     *
     * @param string $appId             Client application ID
     * @param string $appName           Client application name
     * @param int $expirySeconds        Token expiry time in seconds
     * @param array<string> $audience   A list of web service names that can consume the token
     * @param string $kmsMasterKeyId    ID of KMS key used to create encryption data
     * @param int $userId               User ID
     * @param string $userEmail         User email address
     * @param bool $userIsEmailVerified Indicates whether or not the user has verified their email address
     * @param array $scopes            Scopes of access for the user
     * @param string $refreshTokenId    ID of Refresh Token that "produces" this Access token
     *
     * @return self
    */
    public function create(
        string $appId,
        string $appName,
        int $expirySeconds,
        array $audience,
        string $kmsMasterKeyId,
        int $userId,
        string $userEmail,
        bool $userIsEmailVerified,
        array $scopes,
        string $refreshTokenId,
        int $issuedAt = null
    ): self;

    /**
     * Check the presence and validity of the claims within an access token
     *
     * @param string    $webServiceUri     The URI of the validating web service
     * @param \Memcached $memcache Memcache connection
     *
     * @throws TokenExpiredException
     * @throws InvalidAudienceClaimException
     * @throws InvalidSubjectClaimException
     * @throws InvalidIssuerClaimException
     * @throws CriticalClaimsVerificationException
     * @throws UnhandledTokenCheckException
     */
    public function validate(string $webServiceUri, \Memcached $memcache): void;

    /**
     * Create the token from a JSON string and verify the token's signature
     *
     * @param string                    $tokenString   Base64-encoded JWS token string
     * @param CacheItemPoolInterface    $cache         PSR-6 cache item pool
     *
     * @throws InvalidSignatureException
     */
    public function parseTokenString(
        string $tokenString,
        CacheItemPoolInterface $cache = null
    ): void;
}
