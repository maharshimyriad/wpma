<?php

declare(strict_types=1);

namespace Wpma\Models;

/**
 * VariableRef — a variable reference extracted from the token stream.
 */
readonly class VariableRef
{
    /**
     * @param string $name         The variable name including the leading '$'
     *                             (e.g. '$_POST', '$userId').
     * @param int    $line         The 1-based line number where the variable appears.
     * @param bool   $isUserInput  True when the variable is one of the PHP superglobals
     *                             that carry untrusted user-supplied data:
     *                             $_POST, $_GET, $_REQUEST, $_COOKIE,
     *                             $_SERVER, $_FILES.
     */
    public function __construct(
        public string $name,
        public int    $line,
        public bool   $isUserInput,
    ) {}
}
