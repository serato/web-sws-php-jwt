<?php
declare(strict_types=1);

namespace Serato\Jwt\Test;

use Aws\Sdk;
use Aws\Result;
use Aws\MockHandler;
use \PHPUnit\Framework\TestCase;
use Serato\Jwt\AccessToken;
// use Mockery;
// use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;

/**
 * Unit and integration tests for Serat\Jwt\Access
 */
class AccessTokenTest extends TestCase
{
    private const CLIENT_APP_ID = '123abc';
    private const CLIENT_APP_NAME = 'my app';
    private const CLIENT_APP_ACCESS_TOKEN_EXPIRY_SECONDS = 10;
    private const CLIENT_APP_ACCESS_TOKEN_DEFAULT_AUDIENCE = [
        'profile.serato.com',
        'ai-proxy.serato.com',
        'cloudlib.serato.com'
    ];
    private const CLIENT_APP_KMS_MASTER_KEY_ID = 'master-key-xyz';
    private const USER_ID = 987654;
    private const USER_EMAIL = 'user@example.net';
    private const USER_EMAIL_IS_VERIFIED = false;
    private const USER_SCOPES_OF_ACCESS = [
        'profile.serato.com' => ['profile-edit'],
        'ai-proxy.serato.com' => ['user-read'],
        'cloudlib.serato.com' => ['user-read']
    ];
    private const REFRESH_TOKEN_ID = 'rftid-456-def';

    private const ENCRYPTION_KEY_CIPHERTEXT = '48d7fgd87gfd97vs8sdsd7df7s87';
    private const ENCRYPTION_KEY_PLAINTEXT = '123456789abcdefg';

    /**
     * Tests that the AccessToken::getClaims method returns the expected results
     */
    public function testGetClaim(): void
    {
        $token = $this->getToken();
    
        // Standard JWT claims
        $this->assertEquals($token->getClaim('aud'), self::CLIENT_APP_ACCESS_TOKEN_DEFAULT_AUDIENCE);
        $this->assertEquals($token->getClaim('iss'), 'id.serato.io');
        $this->assertEquals($token->getClaim('sub'), 'access');
        $this->assertEquals($token->getClaim('exp'), $token->getClaim('iat') + self::CLIENT_APP_ACCESS_TOKEN_EXPIRY_SECONDS);
        // Serato-specific claims
        $this->assertEquals($token->getClaim('app_id'), self::CLIENT_APP_ID);
        $this->assertEquals($token->getClaim('app_name'), self::CLIENT_APP_NAME);
        $this->assertEquals($token->getClaim('uid'), self::USER_ID);
        $this->assertEquals($token->getClaim('email'), self::USER_EMAIL);
        $this->assertEquals($token->getClaim('email_verified'), self::USER_EMAIL_IS_VERIFIED);
        $this->assertEquals($token->getClaim('scopes'), self::USER_SCOPES_OF_ACCESS);
        $this->assertEquals($token->getClaim('rtid'), self::REFRESH_TOKEN_ID);
    }

    /**
     * Tests that the AccessToken::getProtectedHeader method returns the expected results
     */
    public function testGetProtectedHeaders(): void
    {
        $token = $this->getToken();

        // `aid` header = client application ID
        $this->assertEquals($token->getProtectedHeader('aid'), self::CLIENT_APP_ID);
        // `kct` header = base64 encoded KMS ciphertext
        $this->assertEquals(base64_decode($token->getProtectedHeader('kct')), self::ENCRYPTION_KEY_CIPHERTEXT);
        // `kid` is a unique identifer for the token. We don't know it's value but should check that it exists.
        $this->assertTrue(is_string($token->getProtectedHeader('kid')));
    }

    /**
     * Smoke tests that an AccessToken implements __toString()
     */
    public function testToString(): void
    {
        $token = $this->getToken();
        $this->assertTrue(is_string((string)$token));
    }

    private function getAwsSdk() : Sdk
    {
        $mock = new MockHandler();
        
        // We can "hard code" the MockHandler results queue for all tests because,
        // within the tests contained within this test case, the KmsToken class
        // always makes two calls to the KMS service in the same order of execution.
        
        // Result returned by KmsClient::generateDataKey
        $mock->append(
            new Result([
                'CiphertextBlob' => self::ENCRYPTION_KEY_CIPHERTEXT,
                'Plaintext' => self::ENCRYPTION_KEY_PLAINTEXT
            ])
        );

        // Result returned by KmsClient::decrypt
        $mock->append(new Result([ 'Plaintext' => self::ENCRYPTION_KEY_PLAINTEXT ]));

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

    private function getToken(): AccessToken
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
            self::REFRESH_TOKEN_ID
        );
    }
}
