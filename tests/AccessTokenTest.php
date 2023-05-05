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
    /**
     * @param array<mixed> $params
     * @return IAccessToken
     */
    protected function getToken(array $params = null): IAccessToken
    {
        if ($params === null) {
            $params = $this->getDefaultTokenParams();
        }
        $token = new AccessToken($this->getAwsSdk());
        return $token->create(
            $params['client_app_id'],
            $params['client_app_name'],
            $params['expires'],
            $params['audience'],
            $params['master_key_id'],
            $params['user_id'],
            $params['user_email'],
            $params['user_email_verified'],
            $params['scopes'],
            $params['refresh_token_id'],
            isset($params['subject']) ? $params['subject'] : null,
            isset($params['issued_by']) ? $params['issued_by'] : null,
            isset($params['issued_at']) ? $params['issued_at'] : null
        );
    }
}
