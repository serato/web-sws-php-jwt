<?php
declare(strict_types=1);

namespace Serato\Jwt\Test;

use Mockery;

/**
 * Unit test for classes that implement Serato\Jwt\IAccessToken
 */
abstract class IAccessTokenTest extends ITokenTest
{
    /**
     * @expectedException \Serato\Jwt\Exception\TokenExpiredException   
     */
    public function testExpiredIssuedAt(): void
    {
        $expiredIssuedAt = time() - self::CLIENT_APP_ACCESS_TOKEN_EXPIRY_SECONDS - 5;
        $token = $this->getToken($expiredIssuedAt);

        $mockMemcached = Mockery::mock(\Memcached::class);
        $mockMemcached->shouldReceive('get')->andReturn(false);

        $token->validate(self::CLIENT_APP_ACCESS_TOKEN_DEFAULT_AUDIENCE[0], $mockMemcached);
    }
}
