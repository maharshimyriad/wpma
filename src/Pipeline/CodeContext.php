<?php

declare(strict_types=1);

namespace Wpma\Pipeline;

use Wpma\Models\Token;

/**
 * CodeContext — classifies tokens into executable vs non-executable PHP.
 *
 * Non-executable contexts that must NEVER trigger detections:
 *  - Single-line comments  (T_COMMENT starting with //)
 *  - Multi-line comments   (T_COMMENT /* ... *\/)
 *  - PHPDoc blocks         (T_DOC_COMMENT)
 *  - String literals       (T_CONSTANT_ENCAPSED_STRING, T_ENCAPSED_AND_WHITESPACE)
 *  - Heredoc/nowdoc content
 *  - HTML outside PHP tags (T_INLINE_HTML)
 */
class CodeContext
{
    /**
     * Given the full token stream, return only tokens that are in
     * executable PHP code context (not comments, strings, HTML).
     *
     * @param  Token[] $tokens
     * @return Token[]
     */
    public static function executableOnly(array $tokens): array
    {
        return array_values(array_filter($tokens, [self::class, 'isExecutable']));
    }

    /**
     * Returns true if this token is part of executable PHP code.
     */
    public static function isExecutable(Token $token): bool
    {
        return match ($token->id) {
            // Comments — never executable
            T_COMMENT,
            T_DOC_COMMENT     => false,

            // String literals — content is data, not code
            T_CONSTANT_ENCAPSED_STRING,
            T_ENCAPSED_AND_WHITESPACE,
            T_START_HEREDOC,
            T_END_HEREDOC     => false,

            // HTML outside PHP tags
            T_INLINE_HTML     => false,

            // Whitespace — not code but harmless to include
            // (callers can filter separately if needed)
            T_WHITESPACE      => false,

            default           => true,
        };
    }

    /**
     * Extract the raw text of all comments in the token stream.
     * Useful for detectors that want to log "found in comment, skipped".
     *
     * @param  Token[] $tokens
     * @return string[]
     */
    public static function comments(array $tokens): array
    {
        $out = [];
        foreach ($tokens as $t) {
            if ($t->id === T_COMMENT || $t->id === T_DOC_COMMENT) {
                $out[] = $t->text;
            }
        }
        return $out;
    }

    /**
     * Strip all non-executable content from a raw PHP source string.
     * Returns only the executable PHP code portions — useful for regex-based
     * detectors that operate on raw source rather than the token stream.
     *
     * Strategy:
     *  1. Tokenize with token_get_all()
     *  2. Replace each non-executable token with whitespace of the same length
     *     (preserves line numbers for accurate line reporting)
     *  3. Return the result
     */
    public static function stripNonExecutable(string $source): string
    {
        if (empty($source)) {
            return $source;
        }

        $result = '';
        try {
            $raw = @token_get_all($source, TOKEN_PARSE);
        } catch (\Throwable) {
            // If tokenization fails, return source as-is — detectors will be
            // conservative since they can't reliably strip non-executable content
            return $source;
        }

        foreach ($raw as $entry) {
            if (is_array($entry)) {
                [$id, $text] = $entry;
                $keep = match ($id) {
                    T_COMMENT,
                    T_DOC_COMMENT,
                    T_CONSTANT_ENCAPSED_STRING,
                    T_ENCAPSED_AND_WHITESPACE,
                    T_START_HEREDOC,
                    T_END_HEREDOC,
                    T_INLINE_HTML => false,
                    default       => true,
                };

                if ($keep) {
                    $result .= $text;
                } else {
                    // Preserve newlines so line numbers stay accurate
                    $result .= preg_replace('/[^\n]/', ' ', $text);
                }
            } else {
                // Single-char punctuation token — always executable
                $result .= $entry;
            }
        }

        return $result;
    }
}
