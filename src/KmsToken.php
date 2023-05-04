<?php
declare(strict_types=1);

namespace Serato\Jwt;

use Aws\Sdk as AwsSdk;
use Aws\Result;
use DateTime;
use Ramsey\Uuid\Uuid;
use Psr\Cache\CacheItemPoolInterface;
use InvalidArgumentException;
use Serato\Jwt\Exception\InvalidSignatureException;
use Serato\Jwt\Exception\TokenExpiredException;
use Serato\Jwt\Exception\InvalidAudienceClaimException;
use Serato\Jwt\Exception\InvalidSubjectClaimException;
use Serato\Jwt\Exception\InvalidIssuerClaimException;
use Serato\Jwt\Exception\InvalidJsonStringException;
use Serato\Jwt\Exception\CriticalClaimsVerificationException;
use Serato\Jwt\Exception\UnhandledTokenCheckException;
use Serato\Jwt\Checker\IssuerChecker;
use Serato\Jwt\Checker\SubjectChecker;
use Jose\Factory\JWSFactory;
use Jose\Factory\JWKFactory;
use Jose\Object\JWK;
use Jose\Object\JWS;
use Jose\Object\JWKSet;
use Jose\Signer;
use Jose\Loader;
use Jose\Verifier;
use Jose\Checker\CheckerManager;
use Jose\Checker\CriticalHeaderChecker;
use Jose\Checker\ExpirationTimeChecker;
use Jose\Checker\AudienceChecker;
use Assert\InvalidArgumentException as AssertInvalidArgumentException;
use Exception;
/**
 * Provides functionality to allow the use of the AWS KMS service to create
 * and encrypt hashing secrets in JWTs.
 */
abstract class KmsToken implements IToken
{
    /**
     * The KMS key spec used to create hashing secrets
     */
    const KMS_KEY_SPEC = 'AES_128';

    /**
     * The name of the JWT header that stores the client application ID
     */
    const APP_ID_HEADER_NAME = 'aid';
    
    /**
     * The name of the JWT header that stores the encrypted hash secret
     */
    const KEY_CIPHERTEXT_HEADER_NAME = 'kct';
    
    /**
     * The name of the JWT header that stores a cache id for the encrypted hash secret
     */
    const KEY_ID_HEADER_NAME = 'kid';

    /**
     * The algorithm used to generate the JWS signature
     */
    private const SIGNER_ALG = 'HS512';

    /**
     * JWS token object
     *
     * @var JWS
     */
    private $token;

    /**
     * The value of the `iat` reserved claim within the JWT token
     */
    protected const ISSUED_BY = 'id.serato.io';

    /** @var AwsSdk */
    private $aws;

    /**
     * Constructs the class
     *
     * @param AwsSdk  $aws AWS client
     * @return void
     */
    public function __construct(AwsSdk $aws)
    {
        $this->aws = $aws;
    }

    /**
     * @inheritdoc
     */
    public function getAws(): AwsSdk
    {
        return $this->aws;
    }

    /**
     * @inheritDoc
     */
    final public function __toString(): string
    {
        return $this->token->toCompactJSON(0);
    }

    /**
     * @inheritDoc
     */
    final public function getClaim(string $key)
    {
        return $this->token->getClaim($key);
    }

    /**
     * @inheritDoc
     */
    final public function getProtectedHeader(string $key)
    {
        $sig = $this->token->getSignatures();
        return $sig[0]->getProtectedHeader($key);
    }


    /**
     * @inheritDoc
     */
    public static function setInvalidRefreshTokenIdCacheItem(
        \Memcached $memcache,
        string $refreshTokenId,
        int $ttl
    ): bool {
    
        return $memcache->add(self::getRefreshTokenIdCacheKey($refreshTokenId), $refreshTokenId, $ttl);
    }

    /**
     * @inheritDoc
     */
    public static function getInvalidRefreshTokenIdCacheItem(
        \Memcached $memcache,
        string $refreshTokenId
    ): ?string {
    
        $cacheItem = $memcache->get(self::getRefreshTokenIdCacheKey($refreshTokenId));
        if ($cacheItem === false) {
            return null;
        }
        return $cacheItem;
    }

    /**
     * Gets a cache key for the given refresh token ID
     *
     * @param string $refreshTokenId Refresh token ID
     * @return string
     */
    private static function getRefreshTokenIdCacheKey(string $refreshTokenId): string
    {
        return 'r-' .  $refreshTokenId;
    }

    /**
     * Parse a JSON compact notation string that includes a hash secret encrypted
     * with the AWS KMS service, and use this hash secret to verify the token's
     * signature
     *
     * @todo Specify void return type in PHP 7.1
     *
     * @param string                    $json      JSON-encoded token payload
     * @param string                    $keyId     Name of signing key
     * @param CacheItemPoolInterface    $cache     PSR-6 cache item pool
     *
     * @return void
     *
     * @throws InvalidSignatureException
     */
    final protected function parseBase64EncodedTokenDataWithKms(
        string $json,
        string $keyId,
        CacheItemPoolInterface $cache = null
    ) {
        $this->parseBase64EncodedTokenData($json);
        $this->verifySignature(
            $keyId,
            $this->getPlaintextEncryptionKey($cache)
        );
    }

    /**
     * Return the plaintext encryption key for the token. A optional cache pool
     * can be provided to minimise round trips to KMS to decrypt the plaintext key
     * from the key cipher text.
     *
     * @param CacheItemPoolInterface    $cache   PSR-6 cache item pool
     *
     * @return string
     */
    private function getPlaintextEncryptionKey(CacheItemPoolInterface $cache = null)
    {
        if ($cache === null) {
            return $this->decryptCipherTextEncryptionKey();
        } else {
            $key = $this->getCacheKey(
                $this->getProtectedHeader(self::APP_ID_HEADER_NAME),
                $this->getProtectedHeader(self::KEY_ID_HEADER_NAME)
            );

            // Look for the plaintext key in the cache
            $item = $cache->getItem($key);
            if ($item->isHit()) {
                return $item->get();
            }

            // Doesn't exist. So decrypt it from the cipher text.
            $plaintext = $this->decryptCipherTextEncryptionKey();

            // Add it to the cache
            $expiryTime = new DateTime();
            $expiryTime->setTimestamp($this->getClaim('exp'));
            $item->set($plaintext);
            $item->expiresAt($expiryTime);
            $cache->save($item);

            return $plaintext;
        }
    }

    /**
     * Create a cache key
     *
     * @param string $clientAppId   Client Application ID
     * @param string $keyId                 Unique ID
     *
     * @return string
     */
    private function getCacheKey(string $clientAppId, string $keyId)
    {
        return "Jwt-Kms-" . $clientAppId . '-' . $keyId;
    }

    /**
     * Extract the encryption key cipher text and decrypt the plaintext encryption
     * key from it using AWS KMS
     *
     * @return string
     */
    private function decryptCipherTextEncryptionKey()
    {
        $result = $this->getAws()->createKms()->decrypt([
            'CiphertextBlob' => base64_decode($this->getProtectedHeader(self::KEY_CIPHERTEXT_HEADER_NAME))
        ]);
        return $result['Plaintext'];
    }

    /**
     * Construct a JWS token using a hashing secret generated by the AWS KMS service
     *
     * @todo Specify void return type in PHP 7.1
     *
     * @param string        $clientAppKmsMasterKeyId      Client Application KMS Master Key
     * @param string        $clientAppId                  Client Application ID
     * @param array         $audience                     JWT `aud` claim
     * @param string        $subject                      JWT `sub` claim
     * @param int           $issuedAtTime                 JWT `iat` claim
     * @param int           $expiresAtTime                JWT `exp` claim
     * @param array         $customClaims                 Custom JWT claims
     * @param string        $signingKeyId                 Name of signing key
     *
     * @return void
     */
    final protected function createTokenWithKms(
        string $clientAppKmsMasterKeyId,
        string $clientAppId,
        array $audience,
        string $subject,
        int $issuedAtTime,
        int $expiresAtTime,
        array $customClaims,
        string $signingKeyId
    ) {
        // Generate a new hashing secret key
        $generatedKey = $this->generateKeyData($clientAppKmsMasterKeyId);
        // Create the token
        $this->createToken(
            $audience,
            $subject,
            $issuedAtTime,
            $expiresAtTime,
            $customClaims,
            $this->getTokenKeyHeaders($clientAppId, base64_encode($generatedKey['CiphertextBlob'])),
            $signingKeyId,
            $generatedKey['Plaintext']
        );
    }

    /**
     * Create an array of token headers that store the encrypted key data
     *
     * @param string        $clientAppId    Client Application ID
     * @param string        $ciphertext     The encrypted data encryption key
     * @returns array
     */
    private function getTokenKeyHeaders(string $clientAppId, string $ciphertext): array
    {
        return [
            // Client application ID
            self::APP_ID_HEADER_NAME => $clientAppId,
            // A GUID to be used a caching key
            self::KEY_ID_HEADER_NAME => Uuid::uuid4()->toString(),
            // Encrypted secret key blob from KMS
            self::KEY_CIPHERTEXT_HEADER_NAME => $ciphertext
        ];
    }

    /**
     * Check the validity of the claims within a token
     *
     * @todo Specify void return type in PHP 7.1
     *
     * @param string    $aud    Expected value of `aud` claim
     * @param string    $sub    Expected value of `sub` claim
     *
     * @return void
     *
     * @throws TokenExpiredException
     * @throws InvalidAudienceClaimException
     * @throws InvalidSubjectClaimException
     * @throws InvalidIssuerClaimException
     * @throws CriticalClaimsVerificationException
     * @throws UnhandledTokenCheckException
     */
    final protected function checkClaims(string $aud, string $sub)
    {
        $checkerManager = new CheckerManager();
        // `crit` header
        $checkerManager->addHeaderChecker(new CriticalHeaderChecker());
        // `iss` claim
        $checkerManager->addClaimChecker(new IssuerChecker(self::ISSUED_BY));
        // `exp` claim
        $checkerManager->addClaimChecker(new ExpirationTimeChecker());
        // `aud` claim
        $checkerManager->addClaimChecker(new AudienceChecker($aud));
        // `sub` claim
        $checkerManager->addClaimChecker(new SubjectChecker($sub));

        try {
            $checkerManager->checkJWS($this->token, 0);
        } catch (AssertInvalidArgumentException $e) {
            switch ((int)$e->getCode()) {
                // `exp`
                case 212:
                case 213:
                    throw new TokenExpiredException;
                    break;
                // `aud`
                case 22:
                    throw new InvalidAudienceClaimException;
                    break;
                case 32:
                    // `sub`
                    if (strpos(strtolower($e->getMessage()), 'subject')) {
                        throw new InvalidSubjectClaimException;
                    }
                    // `iss`
                    if (strpos(strtolower($e->getMessage()), 'issuer')) {
                        throw new InvalidIssuerClaimException;
                    }
                    // `crit` header doesn't validate.
                    // Should only ever happen at dev time. Re-throw the exception.
                    if (strpos(strtolower($e->getMessage()), 'marked as critical')) {
                        throw new CriticalClaimsVerificationException($e->getMessage());
                    }
                    break;
                default:
                    throw new UnhandledTokenCheckException($e->getMessage(), $e->getCode());
            }
        }
    }

    /**
     * Parse a JSON compact notation string and verfiy the provided signature
     *
     * @todo Specify void return type in PHP 7.1
     *
     * @param string $tokenString    Base64-encoded JWS token string
     *
     * @return void
     *
     * @throws InvalidSignatureException
     */
    final protected function parseBase64EncodedTokenData(string $tokenString)
    {
        $loader = new Loader();
        try {
            $token = $loader->load($tokenString);
            if (!is_a($token, '\Jose\Object\JWS')) {
                throw new InvalidJsonStringException;
            }
            $this->token = $token;
        } catch (InvalidArgumentException $e) {
            throw new InvalidJsonStringException;
        }
    }

    /**
     * Verify the signature of the token
     *
     * @todo Specify void return type in PHP 7.1
     *
     * @param string    $keyId      Name of signing key
     * @param string    $key        Value of signing key
     *
     * @return void
     *
     * @throws InvalidSignatureException
     */
    final protected function verifySignature(string $keyId, string $key)
    {
        if ($this->token !== null) {
            $jwkSet = new JWKSet();
            $jwkSet->addKey($this->getSigner($keyId, $key));
            $verifier = Verifier::createVerifier([self::SIGNER_ALG]);
            try {
                $verifier->verifyWithKeySet($this->token, $jwkSet, null, $signature_index);
            } catch (InvalidArgumentException $e) {
                throw new InvalidSignatureException;
            }
        }
    }

    /**
     * Construct a JWS token
     *
     * @todo Specify void return type in PHP 7.1
     *
     * @param array     $audience           JWT `aud` claim
     * @param string    $subject            JWT `sub` claim
     * @param int       $issuedAtTime       JWT `iat` claim
     * @param int       $expiresAtTime      JWT `exp` claim
     * @param array     $customClaims       Custom JWT claims
     * @param array     $customHeaders      Custom JWT headers
     * @param string    $signingKeyId       Name of signing key
     * @param string    $signingKey         Value of signing key
     *
     * @return void
     */
    final protected function createToken(
        array $audience,
        string $subject,
        int $issuedAtTime,
        int $expiresAtTime,
        array $customClaims,
        array $customHeaders,
        string $signingKeyId,
        string $signingKey,
        // For testing use only. Not part of the public API
        string $issuedBy = null,
        // For testing use only. Not part of the public API
        array $crit = null
    ) {
        $claims = [
            'iss' => $issuedBy ?? self::ISSUED_BY,
            'aud' => $audience,
            'sub' => $subject,
            'iat' => $issuedAtTime,
            'exp' => $expiresAtTime
        ];

        $jws = JWSFactory::createJWS(array_merge($claims, $customClaims));

        /*
        FYI, the `crit` header lists all of the claims in the payload that must be "checked".
        ie. They must be present in the payload and must be subjected to a verification
        step via a class that implements the Jose\Checker\ClaimCheckerInterface interface.

        The `crit` header itself is checked via the Jose\Checker\CriticalHeaderChecker class.
        
        See self::checkClaims for implementation of checkers.
        */

        $jws = $jws->addSignatureInformation(
            $this->getSigner($signingKeyId, $signingKey),
            array_merge(
                [
                    'alg' => self::SIGNER_ALG,
                    'crit' => $crit ?? ['iss', 'aud', 'sub', 'exp']
                ],
                $customHeaders
            )
        );

        $signer = Signer::createSigner([self::SIGNER_ALG]);
        $signer->sign($jws);

        $this->token = $jws;
    }
 
    /**
     * Generate key data using the AWS KMS service
     *
     * @param string     $clientAppKmsMasterKeyId  Client Application KMS Master Key
     * @returns Result
     */
    private function generateKeyData(string $clientAppKmsMasterKeyId): Result
    {
        return $this->getAws()->createKms()->generateDataKey([
            'KeySpec' => self::KMS_KEY_SPEC,
            'KeyId' => $clientAppKmsMasterKeyId
        ]);
    }

    /**
     * Create a signer object to sign JWS object with
     *
     * @param string $keyId     Name of signing key
     * @param string $key       Value of signing key
     *
     * @return JWK
     */
    private function getSigner(string $keyId, string $key): JWK
    {
        $jwt = JWKFactory::createFromValues(
            [
                'alg' => self::SIGNER_ALG,
                'kty' => 'oct',
                'kid' => $keyId,
                'use' => 'sig',
                'k'   => $key,
            ]
        );
        # JWKFactory::createFromValues can return either a `Jose\Object\JWK` or `Jose\Object\JWKSet` depending
        # on the argument array.
        # In our usage it always returns a `Jose\Object\JWK`.
        # This type check is added so that phpstan is happy with the return value of this function, but in practice
        # the Exception will never be thrown because of how we construct the argument array for the
        # JWKFactory::createFromValues method call.
        if (!is_a($jwt, '\Jose\Object\JWK')) {
            throw new Exception('Error');
        }
        return $jwt;
    }
}
