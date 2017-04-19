<?php

namespace Serato\Jwt\Checker;

use Jose\Checker\SubjectChecker as SubjectCheckerChecker;

class SubjectChecker extends SubjectCheckerChecker
{
    private $subject;

    public function __construct(string $subject)
    {
        $this->subject = $subject;
    }

    protected function isSubjectAllowed($subject)
    {
        return $subject === $this->subject;
    }
}
