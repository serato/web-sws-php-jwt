<?php
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
 * Access Token
 *
 * A represent of a JWS `access` token.
 */
class AccessToken extends AbstractKmsToken
{
    const TOKEN_CLAIM_SUB = 'access';
    const TOKEN_SIGNING_KEY_ID = 'JWS_ACCESS_COMPACT_HS512';

    /**
     * Check the presence and validity of the claims within a refresh token
     *
     * @todo Specify void return type in PHP 7.1
     *
     * @param string    $webServiceUri     The URI of the validating web service
     *
     * @throws TokenExpiredException
     * @throws InvalidAudienceClaimException
     * @throws InvalidSubjectClaimException
     * @throws InvalidIssuerClaimException
     * @throws CriticalClaimsVerificationException
     * @throws UnhandledTokenCheckException
     */
    final public function validate(string $webServiceUri)
    {
        $this->checkClaims($webServiceUri, self::TOKEN_CLAIM_SUB);
    }

     /**
     * Create the token from a JSON string and verify the token's signature
     *
     * @todo Specify void return type in PHP 7.1
     *
     * @param string                    $token   JSON-encoded token payload
     * @param CacheItemPoolInterface    $cache  PSR-6 cache item pool
     *
     * @throws InvalidSignatureException
     */
    final public function createFromToken(
        string $token,
        CacheItemPoolInterface $cache = null
    ) {
        $this->createTokenFromJsonWithKms(
            $token,
            self::TOKEN_SIGNING_KEY_ID,
            $cache
        );
    }
}
