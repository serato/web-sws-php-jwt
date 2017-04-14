<?php
namespace Serato\Jwt;

use InvalidArgumentException;
use Serato\Jwt\Exception\InvalidSignatureException;
use Serato\Jwt\Exception\TokenExpiredException;
use Serato\Jwt\Exception\InvalidAudienceClaimException;
use Serato\Jwt\Exception\InvalidSubjectClaimException;
use Serato\Jwt\Exception\InvalidIssuerClaimException;
use Serato\Jwt\Exception\InvalidJsonStringException;
use Serato\Jwt\Exception\CriticalClaimsVerificationException;
use Serato\Jwt\Exception\UnhandledTokenCheckException;
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
use Serato\Jwt\Checker\IssuerChecker;
use Jose\Checker\ExpirationTimeChecker;
use Jose\Checker\AudienceChecker;
use Serato\Jwt\Checker\SubjectChecker;
use Assert\InvalidArgumentException as AssertInvalidArgumentException;

/**
 * Abstract Token
 *
 * A helper class for creating and validating JSON Web Signatures (JWS).
 *
 * Wraps some functionality around the `spomky-labs/jose` library and encapsulates
 * it entirely within this class should we decide to migrate to a new library.
 *
 * See https://github.com/Spomky-Labs/jose for documentation.
 */
abstract class AbstractToken
{
    /**
     * The value of the `iat` reserved claim within a JWT token
     */
    const ISSUED_BY = 'id.serato.io';
    const SIGNER_ALG = 'HS512';

    /**
     * JWS token object
     *
     * @var JWS
     */
    private $token;

    final public function __toString(): string
    {
        if (!is_null($this->token)) {
            // Call Jose\Object\JWS::toCompactJSON
            return $this->token->toCompactJSON(0);
        }
        return '';
    }

    /**
     * Get a claim's value from a token
     *
     * @param string $key   Name of claim
     *
     * @return mixed
     */
    final public function getClaim(string $key)
    {
        if (!is_null($this->token)) {
            return $this->token->getClaim($key);
        }
        return null;
    }

    /**
     * Get a protected header's value from a token
     *
     * @param string $key   Name of header
     *
     * @return mixed
     */
    final public function getProtectedHeader(string $key)
    {
        if (!is_null($this->token)) {
            $sig = $this->token->getSignatures();
            return $sig[0]->getProtectedHeader($key);
        }
        return null;
    }

    /**
     * Check the presence and validity of the claims within a token
     *
     * @todo Specify void return type in PHP 7.1
     *
     * @param string    $aud    Expected value of `aud` claim
     * @param string    $sub    Expected value of `sub` claim
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
        // For the time, by good fortune, we're only interested in checking the same claims
        // for both refresh and access tokens.
        // But if this changes we'll need to devise a mechanism to pass in additional claims.

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
     * Create the self::token instance property from a JSON string and verify
     * the token's signature
     *
     * @todo Specify void return type in PHP 7.1
     *
     * @param string $json      JSON-encoded token payload
     *
     * @throws InvalidSignatureException
     */
    final protected function createTokenFromJson(string $json)
    {
        $loader = new Loader();
        try {
            $this->token = $loader->load($json);
            if (get_class($this->token) !== 'Jose\Object\JWS') {
                throw new InvalidJsonStringException;
            }
        } catch (InvalidArgumentException $e) {
            throw new InvalidJsonStringException;
        }
    }

    /**
     * Verify the signature of the self::token instance property
     *
     * @todo Specify void return type in PHP 7.1
     *
     * @param string    $keyId      Name of signing key
     * @param string    $key        Value of signing key
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
     * Create a JWS object and set it the self::token instance property
     *
     * @todo Specify void return type in PHP 7.1
     *
     * @param array     $audience       JWT `aud` claim
     * @param string    $subject        JWT `sub` claim
     * @param int       $issuedAtTime   JWT `iat` claim
     * @param int       $expiresAtTime  JWT `exp` claim
     * @param array     $customClaims   Custom JWT claims
     * @param array     $customHeaders  Custom JWT headers
     * @param string    $signingKeyId   Name of signing key
     * @param string    $signingKey     Value of signing key
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
     * Create a signer object to sign JWS objects with
     *
     * @param string $keyId     Name of signing key
     * @param string $key       Value of signing key
     *
     * @return JWK
     */
    final protected function getSigner(string $keyId, string $key): JWK
    {
        return JWKFactory::createFromValues(
            [
                'alg' => self::SIGNER_ALG,
                'kty' => 'oct',
                'kid' => $keyId,
                'use' => 'sig',
                'k'   => $key,
            ]
        );
    }
}
