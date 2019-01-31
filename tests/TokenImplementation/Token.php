<?php
declare(strict_types=1);

namespace Serato\Jwt\Test\TokenImplementation;

use Serato\Jwt\Token as JwtToken;

class Token extends JwtToken
{
    protected $audience = ['audience.member'];
    protected $signer_id = 'JWS_ACCESS_COMPACT_HS512';
    protected $signer_key = 'abcdefgh';
    protected $sub = 'test subject';

    public function create($issuedBy = null, int $exp = null, array $crit = null, array $headers = [])
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
    public function createFromJson(string $json, bool $verifySig = true)
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
    public function verifyClaims(string $aud = null, string $sub = null)
    {
        $this->checkClaims(
            $aud ?? $this->audience[0],
            $sub ?? $this->sub
        );
    }
}
