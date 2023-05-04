<?php
declare(strict_types=1);

namespace Serato\Jwt;

use Serato\Jwt\Exception\InvalidSignatureException;
use Serato\Jwt\Exception\TokenExpiredException;
use Serato\Jwt\Exception\InvalidAudienceClaimException;
use Serato\Jwt\Exception\InvalidSubjectClaimException;
use Serato\Jwt\Exception\InvalidIssuerClaimException;
use Serato\Jwt\Exception\CriticalClaimsVerificationException;
use Serato\Jwt\Exception\UnhandledTokenCheckException;
use Psr\Cache\CacheItemPoolInterface;

/**
 * Serato JWT Access Token
 *
 * Implements a JWS `access` token.
 */
class AccessToken extends KmsToken
{
    private const TOKEN_CLAIM_SUB = 'access';
    private const TOKEN_SIGNING_KEY_ID = 'JWS_ACCESS_COMPACT_HS512';
    private const REFRESH_TOKEN_ID_CLAIM = 'rtid';

    /**
     * Creates a JWS access token
     *
     * @return self
    */
    final public function create(
        string $clientAppId,
        string $clientAppName,
        int $clientAppAccessTokenExpirySeconds,
        array $clientAppAccessTokenDefaultAudience,
        string $clientAppKmsMasterKeyId,
        int $userId,
        string $userEmail,
        bool $userIsEmailVerified,
        array $userScopesOfAccess,
        string $refreshTokenId
    ): self
    {
        $this->createTokenWithKms(
            $clientAppKmsMasterKeyId,
            $clientAppId,
            $clientAppAccessTokenDefaultAudience,
            self::TOKEN_CLAIM_SUB,
            time(),
            time() + $clientAppAccessTokenExpirySeconds,
            [
                'app_id'            => $clientAppId,
                'app_name'          => $clientAppName,
                'uid'               => $userId,
                'email'             => $userEmail,
                'email_verified'    => $userIsEmailVerified,
                'scopes'            => $userScopesOfAccess,
                'rtid'              => $refreshTokenId
            ],
            self::TOKEN_SIGNING_KEY_ID
        );
        return $this;
    }

    /**
     * Check the presence and validity of the claims within an access token
     *
     * @todo Specify void return type in PHP 7.1
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
    final public function validate(string $webServiceUri, \Memcached $memcache)
    {
        $this->checkClaims($webServiceUri, self::TOKEN_CLAIM_SUB);
        $rtid = '';
        try {
            $rtid = $this->getClaim(self::REFRESH_TOKEN_ID_CLAIM);
        } catch (\InvalidArgumentException $e) {
            // The access token does not have an rtid. In this case we will simply skip
            // the following validation step
        }

        if ($rtid !== '' && self::getInvalidRefreshTokenIdCacheItem($memcache, $rtid) !== null) {
            // If the parent refresh token ID has been invalidated, treat this access token as expired.
            throw new TokenExpiredException;
        }
    }

     /**
     * Create the token from a JSON string and verify the token's signature
     *
     * @todo Specify void return type in PHP 7.1
     *
     * @param string                    $tokenString   Base64-encoded JWS token string
     * @param CacheItemPoolInterface    $cache         PSR-6 cache item pool
     *
     * @throws InvalidSignatureException
     */
    final public function parseTokenString(
        string $tokenString,
        CacheItemPoolInterface $cache = null
    ) {
        $this->parseBase64EncodedTokenDataWithKms(
            $tokenString,
            self::TOKEN_SIGNING_KEY_ID,
            $cache
        );
    }
}
