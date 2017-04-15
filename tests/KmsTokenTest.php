<?php
namespace Serato\Jwt\Test;

use Aws\Sdk;
use Aws\Result;
use Aws\MockHandler;
use ReflectionClass;
use PHPUnit\Framework\TestCase;
use Serato\Jwt\Test\TokenImplementation\KmsToken;
use Symfony\Component\Cache\Adapter\FilesystemAdapter as FileSystemCachePool;

/**
 * Unit and integration tests for App\Jwt\AccessToken
 */
class KmsTokenTest extends TestCase
{
    const MOCK_ENCRYPTION_KEY = '123456789abcdefg';
    const FILE_SYSTEM_CACHE_NAMESPACE = 'tests';
    const TOKEN_AUDIENCE = ['audience1', 'audience2'];
    const TOKEN_SUBJECT = 'my_sub';
    const TOKEN_KMS_MASTER_KEY = 'FAKE_MASTER_KEY';
    const TOKEN_CLIENT_APP_ID = 'abcd1234';
    const TOKEN_CLIENT_APP_NAME = 'my_client_app';
    const TOKEN_USER_ID = 123;
    const TOKEN_USER_EMAIL = 'test@test.com';
    const TOKEN_EMAIL_VERIFIED = 1;
    const TOKEN_SCOPES = ['scope1', 'scope2'];

    protected static $fileSystemCachePool;

    protected function setUp()
    {
        $this->fileSystemCacheDir = sys_get_temp_dir() . '/fs-cache';
        $this->deleteFileSystemCacheDir();
    }

    protected function tearDown()
    {
        $this->deleteFileSystemCacheDir();
    }

    /**
     * Create a mock token and ensure that the claims are created correctly
     * and that the APP ID is stored in a protected header
     */
    public function testCreateFromUserRefreshToken()
    {
        $token = $this->getMockKmsToken();
        $this->assertEquals(
            $token->getProtectedHeader(KmsToken::APP_ID_HEADER_NAME),
            self::TOKEN_CLIENT_APP_ID
        );
        $this->assertEquals($token->getClaim('app_id'), self::TOKEN_CLIENT_APP_ID);
        $this->assertEquals($token->getClaim('app_name'), self::TOKEN_CLIENT_APP_NAME);
        $this->assertEquals($token->getClaim('uid'), self::TOKEN_USER_ID);
        $this->assertEquals($token->getClaim('email'), self::TOKEN_USER_EMAIL);
        $this->assertEquals($token->getClaim('email_verified'), self::TOKEN_EMAIL_VERIFIED);
        $this->assertEquals($token->getClaim('scopes'), self::TOKEN_SCOPES);
        $this->assertEquals($token->getClaim('aud'), self::TOKEN_AUDIENCE);
        $this->assertEquals($token->getClaim('sub'), self::TOKEN_SUBJECT);
    }

    /**
     * Create a mock token out of an encoded string representation of the token.
     * Confirm the token is valid.
     */
    public function testCreateFromJsonValidAudience()
    {
        $token = $this->getMockKmsToken();

        $newToken = new KmsToken($this->getAwsSdk($this->getMockDecryptResult()));
        $newToken->parseTokenString((string)$token);
        $newToken->validate(self::TOKEN_AUDIENCE[0], self::TOKEN_SUBJECT);
        $newToken->validate(self::TOKEN_AUDIENCE[1], self::TOKEN_SUBJECT);

        $this->assertEquals(
            $token->getProtectedHeader(KmsToken::APP_ID_HEADER_NAME),
            self::TOKEN_CLIENT_APP_ID
        );

        $this->assertEquals($token->getClaim('app_id'), self::TOKEN_CLIENT_APP_ID);
        $this->assertEquals($token->getClaim('app_name'), self::TOKEN_CLIENT_APP_NAME);
        $this->assertEquals($token->getClaim('uid'), self::TOKEN_USER_ID);
        $this->assertEquals($token->getClaim('email'), self::TOKEN_USER_EMAIL);
        $this->assertEquals($token->getClaim('email_verified'), self::TOKEN_EMAIL_VERIFIED);
        $this->assertEquals($token->getClaim('scopes'), self::TOKEN_SCOPES);
        $this->assertEquals($token->getClaim('aud'), self::TOKEN_AUDIENCE);
        $this->assertEquals($token->getClaim('sub'), self::TOKEN_SUBJECT);
    }

    /**
     * Create a mock token out of an encoded string representation of the token.
     * Confirm the token is not valid if tested against an invalid audience.
     *
     * @expectedException Serato\Jwt\Exception\InvalidAudienceClaimException
     */
    public function testCreateFromJsonInvalidAudience()
    {
        $token = $this->getMockKmsToken();
        $newToken = new KmsToken($this->getAwsSdk($this->getMockDecryptResult()));
        $newToken->parseTokenString((string)$token);
        $newToken->validate(self::TOKEN_AUDIENCE[0] . 'bung value', self::TOKEN_SUBJECT);
    }

    /**
     * Test caching functionality
     */
    public function testCreateFromJsonEncryptionKeyCache()
    {
        $token = $this->getMockKmsToken();

        $newToken = new KmsToken($this->getAwsSdk($this->getMockDecryptResult()));
        $newToken->parseTokenString((string)$token, $this->getFileSystemCachePool());

        // Should now have the plaintext encryption key in the cache
        // So use some reflection to get the cache key
        $reflection = new ReflectionClass(get_class($newToken));
        $method = $reflection->getMethod('getCacheKey');
        $method->setAccessible(true);
        $args = [
            $newToken->getProtectedHeader(KmsToken::APP_ID_HEADER_NAME),
            $newToken->getProtectedHeader(KmsToken::KEY_ID_HEADER_NAME)
        ];
        $cacheKey = $method->invokeArgs($newToken, $args);
        
        // Ensure that the item is in the cache
        // TODO: can we test that the expiry time of the cache item matches the expiry
        //       time of the token?
        $item = $this->getFileSystemCachePool()->getItem($cacheKey);
        $this->assertTrue($item->isHit());

        // Create the token again from the same string. This time should use
        // the cached encryption key
        // TODO: don't know how to test a cache hit :-(
        $newToken = new KmsToken($this->getAwsSdk($this->getMockDecryptResult()));
        $newToken->parseTokenString((string)$token, $this->getFileSystemCachePool());
        $this->assertTrue(true);
    }

    private function getMockKmsToken(
        int $issuedAt = null,
        int $expiresAt = null
    ): KmsToken {
        if ($issuedAt === null) {
            $issuedAt = time();
        }
        if ($expiresAt === null) {
            $expiresAt = time() + (60 * 60);
        }

        $token = new KmsToken($this->getAwsSdk($this->getMockGenerateDataKeyResult()));
        return $token->create(
            self::TOKEN_AUDIENCE, // Audience
            self::TOKEN_SUBJECT, // Subject
            $issuedAt, // Issued Time
            $expiresAt, // Expiry Time
            self::TOKEN_KMS_MASTER_KEY,
            self::TOKEN_CLIENT_APP_ID,
            self::TOKEN_CLIENT_APP_NAME,
            self::TOKEN_USER_ID,
            self::TOKEN_USER_EMAIL,
            self::TOKEN_EMAIL_VERIFIED,
            self::TOKEN_SCOPES
        );
    }

    protected function getAwsSdk(Result $result) : Sdk
    {
        $mock = new MockHandler();
        $mock->append($result);

        return new Sdk([
            'region' => 'us-east-1',
            'version' => '2014-11-01',
            'credentials' => [
                'key' => 'my-access-key-id',
                'secret' => 'my-secret-access-key'
            ],
            'handler' => $mock
        ]);
    }

    protected function getMockGenerateDataKeyResult(): Result
    {
        // Result returned by KmsClient::generateDataKey
        return new Result([
            'CiphertextBlob'    => base64_encode(self::MOCK_ENCRYPTION_KEY),
            'Plaintext'         => self::MOCK_ENCRYPTION_KEY
        ]);
    }

    protected function getMockDecryptResult(): Result
    {
        // Result returned by KmsClient::decrypt
        return new Result([
            'Plaintext' => self::MOCK_ENCRYPTION_KEY
        ]);
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
                self::FILE_SYSTEM_CACHE_NAMESPACE,
                0,
                $this->fileSystemCacheDir
            );
        }
        return self::$fileSystemCachePool;
    }

    private function deleteFileSystemCacheDir()
    {
        if ($this->fileSystemCacheDir !== null && is_dir($this->fileSystemCacheDir)) {
            exec('rm -rf '. escapeshellarg($this->fileSystemCacheDir));
        }
    }
}
