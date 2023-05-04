<?php
declare(strict_types=1);

namespace Serato\Jwt;

use Serato\Jwt\Exception\TokenExpiredException;
use Psr\Cache\CacheItemPoolInterface;

/**
 * Serato JWT Access Token
 *
 * Implements a JWS `access` token.
 */
class AccessToken extends KmsToken implements IAccessToken
{
    private const TOKEN_CLAIM_SUB = 'access';
    private const TOKEN_SIGNING_KEY_ID = 'JWS_ACCESS_COMPACT_HS512';
    private const REFRESH_TOKEN_ID_CLAIM = 'rtid';

    /**
     * @inheritdoc
    */
    final public function create(
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
    ): IAccessToken
    {
        if ($issuedAt === null) {
            $issuedAt = time();
        }
        $this->createTokenWithKms(
            $kmsMasterKeyId,
            $appId,
            $audience,
            self::TOKEN_CLAIM_SUB,
            $issuedAt,
            $issuedAt + $expirySeconds,
            [
                'app_id'            => $appId,
                'app_name'          => $appName,
                'uid'               => $userId,
                'email'             => $userEmail,
                'email_verified'    => $userIsEmailVerified,
                'scopes'            => $scopes,
                'rtid'              => $refreshTokenId
            ],
            self::TOKEN_SIGNING_KEY_ID
        );
        return $this;
    }

    /**
     * @inheritdoc
     */
    final public function validate(string $webServiceUri, \Memcached $memcache): void
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
     * @inheritdoc
     */
    final public function parseTokenString(
        string $tokenString,
        CacheItemPoolInterface $cache = null
    ): void {
        $this->parseBase64EncodedTokenDataWithKms(
            $tokenString,
            self::TOKEN_SIGNING_KEY_ID,
            $cache
        );
    }
}
