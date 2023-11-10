<?php
declare(strict_types=1);

namespace Serato\Jwt\Test\TokenImplementation;

use Serato\Jwt\Token as JwtToken;

class Token extends JwtToken
{
    /**
     * @var string[]
     */
    protected $audience = ['audience.member'];
    /**
     * @var string
     */
    protected $signer_id = 'JWS_ACCESS_COMPACT_HS512';
    /**
     * @var string
     */
    protected $signer_key = 'abcdefgh';
    /**
     * @var string
     */
    protected $sub = 'test subject';

    /**
     * @param string|null $issuedBy
     * @param int|null $exp
     * @param array<string>|null $crit
     * @param array<mixed> $headers
     * @return void
     */
    public function create(string $issuedBy = null, int $exp = null, array $crit = null, array $headers = []): void
    {
        $this->createToken(
            $this->audience,
            $this->sub,
            time(),
            $exp ?? time() + (60 * 60),
            ['var1' => 'value1'],
            $headers,
            $this->signer_id,
            $this->signer_key,
            $issuedBy,
            $crit
        );
    }
    /**
     *
     * @todo Specify void return type in PHP 7.1
     */
    public function createFromJson(string $json, bool $verifySig = true): void
    {
        $this->parseBase64EncodedTokenData($json);
        if ($verifySig) {
            $this->verifySignature($this->signer_id, $this->signer_key);
        }
    }

    /**
     *
     * @todo Specify void return type in PHP 7.1
     */
    public function verifyClaims(string $aud = null, string $sub = null): void
    {
        $this->checkClaims(
            $aud ?? $this->audience[0],
            $sub ?? $this->sub
        );
    }
}
