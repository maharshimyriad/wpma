<?php

declare(strict_types=1);

namespace Wpma\Models;

/**
 * Token — a single PHP token from the token_get_all() token stream.
 *
 * @see https://www.php.net/manual/en/function.token-get-all.php
 */
readonly class Token
{
    /**
     * @param int    $id   The PHP token constant (e.g. T_STRING, T_FUNCTION) or -1
     *                     for single-character tokens that have no named constant.
     * @param string $text The raw token text as it appears in the source file.
     * @param int    $line The 1-based line number where this token appears.
     */
    public function __construct(
        public int    $id,
        public string $text,
        public int    $line,
    ) {}

    /**
     * Returns true if this token represents a single-character literal
     * (e.g. '(', ')', ';') rather than a named PHP token constant.
     */
    public function isSingleChar(): bool
    {
        return $this->id === -1;
    }

    /**
     * Human-readable token name for debugging.
     * Returns the PHP token name (e.g. "T_STRING") or the raw character.
     */
    public function name(): string
    {
        if ($this->id === -1) {
            return $this->text;
        }

        return token_name($this->id);
    }
}
