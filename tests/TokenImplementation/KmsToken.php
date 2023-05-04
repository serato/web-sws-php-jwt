<?php
declare(strict_types=1);

namespace Serato\Jwt\Test\TokenImplementation;

use Serato\Jwt\KmsToken as JwtKmsToken;
use Psr\Cache\CacheItemPoolInterface;

class KmsToken extends JwtKmsToken
{
    #const TOKEN_CLAIM_SUB = 'my_subject';
    const TOKEN_SIGNING_KEY_ID = 'JWS_ACCESS_COMPACT_HS512';

    protected $audience = ['audience.member'];
    protected $signer_id = 'JWS_ACCESS_COMPACT_HS512';
    protected $signer_key = 'abcdefgh';
    protected $sub = 'test subject';

    public function create($issuedBy = null, int $exp = null, array $crit = null, array $headers = [])
    {
        $this->createToken(
            $this->audience,
            $this->sub,
            time(),
            $exp ?? time() + (60 * 60),
            ['var1' => 'value1'],
            $headers,
            $this->signer_id,
            $this->signer_key,
            $issuedBy,
            $crit
        );
    }

    /**
     *
     * @todo Specify void return type in PHP 7.1
     */
    public function createFromJson(string $json, bool $verifySig = true)
    {
        $this->parseBase64EncodedTokenData($json);
        if ($verifySig) {
            $this->verifySignature($this->signer_id, $this->signer_key);
        }
    }

    /**
     *
     * @todo Specify void return type in PHP 7.1
     */
    public function verifyClaims(string $aud = null, string $sub = null)
    {
        $this->checkClaims(
            $aud ?? $this->audience[0],
            $sub ?? $this->sub
        );
    }

    /**
     * Create an access token
     *
     * @param array     $audience                   JWT `aud` claim
     * @param string    $subject                    JWT `sub` claim
     * @param int       $issuedAtTime               JWT `iat` claim
     * @param int       $expiresAtTime              JWT `exp` claim
     * @param string    $clientAppKmsMasterKeyId    Client Application KMS Master Key
     * @param string    $clientAppId                Client Application ID
     * @param int       $userId                     User ID
     * @param string    $userEmail                  User Email
     * @param bool      $emailVerified              Email Verification
     * @param array     $scopes                     An array of scopes
     *
     * @return KmsToken
     */
    public function createWithKms(
        array $audience,
        string $subject,
        int $issuedAtTime,
        int $expiresAtTime,
        string $clientAppKmsMasterKeyId,
        string $clientAppId = '',
        string $clientAppName = '',
        int $userId = 0,
        string $userEmail = '',
        bool $emailVerified = true,
        array $scopes = []
    ): KmsToken {
        $customClaims = [
            'app_id'            => $clientAppId,
            'app_name'          => $clientAppName,
            'uid'               => $userId,
            'email'             => $userEmail,
            'email_verified'    => $emailVerified,
            'scopes'            => $scopes
        ];

        $this->createTokenWithKms(
            $clientAppKmsMasterKeyId,
            $clientAppId,
            $audience,
            $subject,
            $issuedAtTime,
            $expiresAtTime,
            $customClaims,
            self::TOKEN_SIGNING_KEY_ID
        );

        return $this;
    }

    public function validate(string $audience, string $subject)
    {
        $this->checkClaims($audience, $subject);
    }

    public function parseTokenString(
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
