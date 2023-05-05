<?php
declare(strict_types=1);

namespace Serato\Jwt\Test;

use Symfony\Component\Cache\Adapter\FilesystemAdapter as FileSystemCachePool;
use Mockery;

/**
 * Unit test for classes that implement Serato\Jwt\IAccessToken
 */
abstract class IAccessTokenTest extends ITokenTest
{
    /** @var string */
    private $fileSystemCacheDir;
    /** @var FileSystemCachePool */
    protected static $fileSystemCachePool;

    protected function setUp(): void
    {
        $this->fileSystemCacheDir = sys_get_temp_dir() . '/fs-cache';
        $this->deleteFileSystemCacheDir();
    }

    protected function tearDown(): void
    {
        $this->deleteFileSystemCacheDir();
    }

    /**
     * @expectedException \Serato\Jwt\Exception\TokenExpiredException
     */
    public function testExpiredIssuedAt(): void
    {
        $params = $this->getDefaultTokenParams();
        $params['issued_at'] = time() - self::CLIENT_APP_ACCESS_TOKEN_EXPIRY_SECONDS - 5;
        $token = $this->getToken($params);

        $mockMemcached = Mockery::mock(\Memcached::class);
        $mockMemcached->shouldReceive('get')->andReturn(false);

        $token->validate($this->getValidAudienceName(), $mockMemcached);
    }

    /**
     * @expectedException \Serato\Jwt\Exception\InvalidAudienceClaimException
     */
    public function testInvalidAudience(): void
    {
        $token = $this->getToken();

        $mockMemcached = Mockery::mock(\Memcached::class);
        $mockMemcached->shouldReceive('get')->andReturn(false);

        $token->validate('not-a-valid-audience-name', $mockMemcached);
    }

    /**
     * @expectedException \Serato\Jwt\Exception\InvalidSubjectClaimException
     */
    public function testInvalidSubject(): void
    {
        $params = $this->getDefaultTokenParams();
        $params['subject'] = 'wrong-subject';
        $token = $this->getToken($params);

        $mockMemcached = Mockery::mock(\Memcached::class);
        $mockMemcached->shouldReceive('get')->andReturn(false);

        $token->validate($this->getValidAudienceName(), $mockMemcached);
    }

    /**
     * @expectedException \Serato\Jwt\Exception\InvalidIssuerClaimException
     */
    public function testInvalidIssuer(): void
    {
        $params = $this->getDefaultTokenParams();
        $params['issued_by'] = 'wrong-issuer';
        $token = $this->getToken($params);

        $mockMemcached = Mockery::mock(\Memcached::class);
        $mockMemcached->shouldReceive('get')->andReturn(false);

        $token->validate($this->getValidAudienceName(), $mockMemcached);
    }

    /**
     * @expectedException \Serato\Jwt\Exception\TokenExpiredException
     */
    public function testInvalidRefreshToken(): void
    {
        $token = $this->getToken();

        $mockMemcached = Mockery::mock(\Memcached::class);
        $mockMemcached->shouldReceive('get')->andReturn(self::REFRESH_TOKEN_ID);

        $token->validate($this->getValidAudienceName(), $mockMemcached);
    }

    public function tesValidToken(): void
    {
        $token = $this->getToken();

        $mockMemcached = Mockery::mock(\Memcached::class);
        $mockMemcached->shouldReceive('get')->andReturn('a-refresh-token-id');

        $this->assertNull($token->validate($this->getValidAudienceName(), $mockMemcached));
    }

    /**
     * @expectedException \Serato\Jwt\Exception\InvalidJsonStringException
     */
    public function testParseTokenStringInvalidJson(): void
    {
        $token = $this->getToken();
        $token->parseTokenString('definitely-not-a-jwt');
    }

    /**
     * @expectedException \Serato\Jwt\Exception\InvalidSignatureException
     */
    public function testParseTokenStringInvalidSignature(): void
    {
        $cache = $this->getFileSystemCachePool();
        $cacheKey = 'my-test-cache-key';
        $item = $cache->getItem($cacheKey);
        $item->set(self::ENCRYPTION_KEY_PLAINTEXT . 'some-extra-nonsense-that-produce-a-different-signature');
        $cache->save($item);

        $token = $this->getToken();
        $token->parseTokenString((string)$token, $cache, $cacheKey);
    }

    /**
     * Gets a PSR-6 compliant file system based cache pool
     *
     * @return FileSystemCachePool
     */
    private function getFileSystemCachePool(): FileSystemCachePool
    {
        if (self::$fileSystemCachePool === null) {
            self::$fileSystemCachePool = new FileSystemCachePool(
                'tests',
                0,
                $this->fileSystemCacheDir
            );
        }
        return self::$fileSystemCachePool;
    }

    private function deleteFileSystemCacheDir(): void
    {
        if ($this->fileSystemCacheDir !== null && is_dir($this->fileSystemCacheDir)) {
            exec('rm -rf '. escapeshellarg($this->fileSystemCacheDir));
        }
    }
}
