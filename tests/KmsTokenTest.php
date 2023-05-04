<?php
declare(strict_types=1);

namespace Serato\Jwt\Test;

use Aws\Sdk;
use Aws\Result;
use Aws\MockHandler;
use Base64Url\Base64Url;
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
    const TOKEN_EMAIL_VERIFIED = true;
    const TOKEN_SCOPES = ['scope1', 'scope2'];

    private $fileSystemCacheDir;
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
     * Create a token, convert it to a string then parse the string
     *
     * @group jwt
     */
    public function testValidParse()
    {
        $token = new KmsToken($this->getAwsSdk());
        $token->create();

        $newToken = new KmsToken($this->getAwsSdk());
        $newToken->createFromJson((string)$token);
        $this->assertEquals((string)$token, (string)$newToken);
    }

    /**
     * Create a token, alter it's payload then parse it but DON'T check the
     * signature. It should parse OK.
     *
     * @group jwt
     */
    public function testPayloadTamperNoSignatureCheck()
    {
        $token = new KmsToken($this->getAwsSdk());
        $token->create();

        $tokenParts = explode('.', (string)$token);
        $jsonString = base64_decode($tokenParts[1]);
        $payload = json_decode($jsonString === false ? '' : $jsonString, true);
        $payload['var1'] = 'fiddled_with';

        $jsonString = json_encode($payload);
        $jsonData = $tokenParts[0] . '.' .
            Base64Url::encode($jsonString === false ? '' : $jsonString) . '.' .
            $tokenParts[2];
        
        $newToken = new KmsToken($this->getAwsSdk());
        $newToken->createFromJson($jsonData, false);
        $this->assertEquals($newToken->getClaim('var1'), 'fiddled_with');
    }

    /**
     * Create a token, alter it's payload, parse and check the signature.
     *
     * @expectedException \Serato\Jwt\Exception\InvalidSignatureException
     * @group jwt
     */
    public function testPayloadTamperSignatureCheck()
    {
        $token = new KmsToken($this->getAwsSdk());
        $token->create();

        $tokenParts = explode('.', (string)$token);

        $jsonString = base64_decode($tokenParts[1]);
        $payload = json_decode($jsonString === false ? '' : $jsonString, true);
        $payload['var1'] = 'fiddled_with';

        $jsonString = json_encode($payload);
        $jsonData = $tokenParts[0] . '.' .
            Base64Url::encode($jsonString === false ? '' : $jsonString) . '.' .
            $tokenParts[2];
        
        $newToken = new KmsToken($this->getAwsSdk());
        $newToken->createFromJson($jsonData);
    }

    /**
     * Check claims.
     * 1. All claims valid (should pass without error)
     *
     * @group jwt
     */
    public function testCheckClaimsAllValid()
    {
        $token = new KmsToken($this->getAwsSdk());
        $token->create();
        $token->verifyClaims();
        $this->assertTrue(true);
    }

    /**
     * Check claims.
     * 2. Invalid issuer
     *
     * @expectedException \Serato\Jwt\Exception\InvalidIssuerClaimException
     * @group jwt
     */
    public function testCheckClaimsInvalidIssuer()
    {
        $token = new KmsToken($this->getAwsSdk());
        $token->create('fake issuer');
        $token->verifyClaims();
    }

    /**
     * Check claims.
     * 3. Invalid expiry date
     *
     * @expectedException \Serato\Jwt\Exception\TokenExpiredException
     * @group jwt
     */
    public function testCheckClaimsTokenExpired()
    {
        $token = new KmsToken($this->getAwsSdk());
        $token->create(null, time() - (2 * 60 * 60));
        $token->verifyClaims();
    }

    /**
     * Check claims.
     * 4. Invalid audience
     *
     * @expectedException \Serato\Jwt\Exception\InvalidAudienceClaimException
     * @group jwt
     */
    public function testCheckClaimsInvalidAudience()
    {
        $token = new KmsToken($this->getAwsSdk());
        $token->create();
        $token->verifyClaims('nonsense.serato.com');
    }

    /**
     * Check claims.
     * 5. Invalid subject
     *
     * @expectedException \Serato\Jwt\Exception\InvalidSubjectClaimException
     * @group jwt
     */
    public function testCheckClaimsInvalidSubject()
    {
        $token = new KmsToken($this->getAwsSdk());
        $token->create();
        $token->verifyClaims(null, 'bung_subject');
    }


    /**
     * Failed check on claims listed in `crit` header
     *
     * @expectedException \Serato\Jwt\Exception\CriticalClaimsVerificationException
     * @group jwt
     */
    public function testFailedCriticalClaimsHeaderCheck()
    {
        $token = new KmsToken($this->getAwsSdk());
        $token->create(null, null, ['iat']);
        $token->verifyClaims();
    }

    /**
     * Test setting and fetching custom protected header
     *
     * @group jwt
     */
    public function testCustomProtectedHeaderValue()
    {
        $headers = [
            'protected_header_1' => 'value_1',
            'protected_header_2' => 'value_2'
        ];
        $token = new KmsToken($this->getAwsSdk());
        $token->create(null, null, null, $headers);

        $this->assertEquals(
            $token->getProtectedHeader('protected_header_1'),
            $headers['protected_header_1']
        );
        $this->assertEquals(
            $token->getProtectedHeader('protected_header_2'),
            $headers['protected_header_2']
        );
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

        $newToken = new KmsToken($this->getAwsSdk());
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
        $newToken = new KmsToken($this->getAwsSdk());
        $newToken->parseTokenString((string)$token);
        $newToken->validate(self::TOKEN_AUDIENCE[0] . 'bung value', self::TOKEN_SUBJECT);
    }

    /**
     * Test caching functionality
     */
    public function testCreateFromJsonEncryptionKeyCache()
    {
        $token = $this->getMockKmsToken();

        $newToken = new KmsToken($this->getAwsSdk());
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
        $newToken = new KmsToken($this->getAwsSdk());
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

        $token = new KmsToken($this->getAwsSdk());
        return $token->createWithKms(
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

    protected function getAwsSdk() : Sdk
    {
        $mock = new MockHandler();
        
        // We can "hard code" the MockHandler results queue for all tests because,
        // within the tests contained within this test case, the KmsToken class
        // always makes two calls to the KMS service in the same order of execution.
        
        // Result returned by KmsClient::generateDataKey
        $mock->append(
            new Result([
                'CiphertextBlob'    => base64_encode(self::MOCK_ENCRYPTION_KEY),
                'Plaintext'         => self::MOCK_ENCRYPTION_KEY
            ])
        );

        // Result returned by KmsClient::decrypt
        $mock->append(
            new Result([
                'Plaintext' => self::MOCK_ENCRYPTION_KEY
            ])
        );

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
