<?php

declare(strict_types=1);

namespace Wpma\Models;

/**
 * FunctionCall — a function or method invocation extracted from the token stream.
 */
readonly class FunctionCall
{
    /**
     * @param string $name      The function name as it appears in source (e.g. "base64_decode").
     * @param array  $args      List of argument expressions as raw string values.
     * @param int    $line      The 1-based line number of the call.
     * @param bool   $isDynamic True when the function name is derived from a variable
     *                          (e.g. $fn(), $$name(), call_user_func($var, ...)).
     */
    public function __construct(
        public string $name,
        public array  $args,
        public int    $line,
        public bool   $isDynamic,
    ) {}
}
