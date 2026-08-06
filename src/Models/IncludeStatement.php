<?php

declare(strict_types=1);

namespace Wpma\Models;

/**
 * IncludeStatement — a file-include or file-require statement extracted from the token stream.
 */
readonly class IncludeStatement
{
    /**
     * @param string $keyword    The include keyword used: 'include', 'include_once',
     *                           'require', or 'require_once'.
     * @param string $path       The include path expression as it appears in source.
     *                           May be a literal string or a full expression string
     *                           when $isDynamic is true.
     * @param int    $line       The 1-based line number of the statement.
     * @param bool   $isDynamic  True when the path contains a variable or expression
     *                           that cannot be resolved statically, making the
     *                           included file attacker-controllable.
     */
    public function __construct(
        public string $keyword,
        public string $path,
        public int    $line,
        public bool   $isDynamic,
    ) {}
}
