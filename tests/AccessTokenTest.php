<?php
declare(strict_types=1);

namespace Serato\Jwt\Test;

use Serato\Jwt\IAccessToken;
use Serato\Jwt\AccessToken;

/**
 * Unit test for the `Serato\Jwt\AccessToken` implementation of `Serato\Jwt\ITokenTest`
 */
class AccessTokenTest extends IAccessTokenTest
{
    protected function getToken(int $issuedAt = null): IAccessToken
    {
        $token = new AccessToken($this->getAwsSdk());
        return $token->create(
            self::CLIENT_APP_ID,
            self::CLIENT_APP_NAME,
            self::CLIENT_APP_ACCESS_TOKEN_EXPIRY_SECONDS,
            self::CLIENT_APP_ACCESS_TOKEN_DEFAULT_AUDIENCE,
            self::CLIENT_APP_KMS_MASTER_KEY_ID,
            self::USER_ID,
            self::USER_EMAIL,
            self::USER_EMAIL_IS_VERIFIED,
            self::USER_SCOPES_OF_ACCESS,
            self::REFRESH_TOKEN_ID,
            $issuedAt
        );
    }
}
