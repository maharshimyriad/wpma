<?php

declare(strict_types=1);

namespace Wpma\Pipeline;

use Wpma\Models\ParseError;
use Wpma\Models\Token;

/**
 * TokenizeResult — the value object returned by PhpTokenizer::tokenize().
 *
 * Contains the flat token stream produced by token_get_all() (normalised into
 * Token objects) and any non-fatal parse errors encountered during tokenisation.
 * When the source could not be tokenised at all, $tokens will be empty and
 * $parseErrors will contain at least one entry.
 */
readonly class TokenizeResult
{
    /**
     * @param Token[]      $tokens      Flat array of Token objects for the source file.
     * @param ParseError[] $parseErrors Non-fatal errors encountered during tokenisation.
     *                                  Detectors can still run on the partial token stream
     *                                  when parse errors are present.
     * @param bool         $success     True if tokenisation produced no parse errors.
     */
    public function __construct(
        public array $tokens,
        public array $parseErrors,
        public bool  $success = true,
    ) {}

    /**
     * Named constructor — derives $success automatically from the parseErrors array.
     *
     * @param Token[]      $tokens
     * @param ParseError[] $parseErrors
     */
    public static function create(array $tokens, array $parseErrors): self
    {
        return new self(
            tokens: $tokens,
            parseErrors: $parseErrors,
            success: $parseErrors === [],
        );
    }
}
