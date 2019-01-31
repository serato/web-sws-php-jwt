<?php
declare(strict_types=1);

namespace Serato\Jwt\Checker;

use Jose\Checker\IssuerChecker as JoseIssuerChecker;

class IssuerChecker extends JoseIssuerChecker
{
    private $issuer;

    public function __construct(string $issuer)
    {
        $this->issuer = $issuer;
    }

    protected function isIssuerAllowed($issuer)
    {
        return $issuer === $this->issuer;
    }
}
