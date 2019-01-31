<?php
declare(strict_types=1);

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
use Serato\Jwt\Checker\IssuerChecker;
use Serato\Jwt\Checker\SubjectChecker;
use Jose\Factory\JWSFactory;
use Jose\Factory\JWKFactory;
use Jose\Object\JWK;
use Jose\Object\JWS;
use Jose\Object\JWKSet;
use Jose\Object\JWKInterface;
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
 * Base class for creating and validating JSON Web Signatures (JWS).
 */
abstract class Token
{
    /**
     * The value of the `iat` reserved claim within the JWT token
     */
    const ISSUED_BY = 'id.serato.io';
    
    /**
     * The algorithm used to generate the JWS signature
     */
    const SIGNER_ALG = 'HS512';

    /**
     * JWS token object
     *
     * @var JWS
     */
    private $token;

    /**
     * Get the compact JSON notation form of the token
     *
     * @return string
     */
    final public function __toString(): string
    {
        return $this->token->toCompactJSON(0);
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
        return $this->token->getClaim($key);
    }

    /**
     * Get a protected header's value from the token
     *
     * @param string $key   Name of header
     *
     * @return mixed
     */
    final public function getProtectedHeader(string $key)
    {
        $sig = $this->token->getSignatures();
        return $sig[0]->getProtectedHeader($key);
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
