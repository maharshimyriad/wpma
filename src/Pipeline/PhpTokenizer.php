<?php

declare(strict_types=1);

namespace Wpma\Pipeline;

use Wpma\Models\ParseError;
use Wpma\Models\Token;

/**
 * PhpTokenizer — wraps PHP's built-in token_get_all() into a safe, structured interface.
 *
 * Converts the raw mixed array returned by token_get_all() (which contains either
 * [id, text, line] arrays or bare single-character strings) into a uniform flat
 * array of Token value objects.
 *
 * This class never throws. All errors are collected into ParseError objects and
 * returned alongside whatever tokens were gathered before the error occurred.
 */
class PhpTokenizer
{
    /**
     * Tokenize PHP source code.
     *
     * Uses PHP's built-in token_get_all() with TOKEN_PARSE so that invalid syntax
     * is reported via ParseErrors rather than triggering a fatal parse error in older
     * PHP versions. Line numbers for single-character punctuation tokens are estimated
     * by counting the newlines that appear in the preceding token stream.
     *
     * @param string $source   Raw PHP source code (must include the opening <?php tag).
     * @param string $filePath Optional file path used to populate ParseError context;
     *                         does not affect tokenisation behaviour.
     *
     * @return TokenizeResult A value object containing the token array and any errors.
     *                        Never throws — errors are always returned in parseErrors.
     */
    public function tokenize(string $source, string $filePath = ''): TokenizeResult
    {
        /** @var Token[]      $tokens */
        $tokens = [];
        /** @var ParseError[] $parseErrors */
        $parseErrors = [];

        try {
            // Handle encoding detection: if mb_detect_encoding fails, convert to UTF-8.
            $detectedEncoding = mb_detect_encoding(
                $source,
                ['UTF-8', 'ISO-8859-1', 'Windows-1252'],
                true,
            );

            if ($detectedEncoding === false) {
                // mb_detect_encoding failed; assume the source is in an unknown encoding
                // and convert it to UTF-8 using mb_convert_encoding's fallback behavior.
                $source = mb_convert_encoding($source, 'UTF-8', 'auto');
            } elseif ($detectedEncoding !== 'UTF-8') {
                // Convert to UTF-8 for consistent tokenization.
                $source = mb_convert_encoding($source, 'UTF-8', $detectedEncoding);
            }

            // Suppress warnings emitted by token_get_all() for recoverable syntax
            // errors; we capture them via set_error_handler below instead.
            $capturedWarnings = [];

            set_error_handler(
                static function (int $errno, string $errstr) use (&$capturedWarnings): bool {
                    $capturedWarnings[] = $errstr;
                    // Returning true prevents PHP from also logging the warning.
                    return true;
                },
                E_WARNING | E_NOTICE,
            );

            try {
                $raw = token_get_all($source, TOKEN_PARSE);
            } finally {
                restore_error_handler();
            }

            // Turn any captured warnings into ParseErrors.
            foreach ($capturedWarnings as $warning) {
                $parseErrors[] = new ParseError(
                    message: $warning,
                    line: 0,
                    context: '',
                );
            }

            // Walk the raw token stream.  token_get_all() returns either:
            //   - [int $id, string $text, int $line]  for named tokens
            //   - string $char                         for single-character punctuation
            //
            // We track the current estimated line number so single-character tokens
            // receive a useful line value rather than 0.
            $currentLine = 1;

            foreach ($raw as $entry) {
                if (is_array($entry)) {
                    // Named token: [id, text, line]
                    [$id, $text, $line] = $entry;
                    $currentLine = $line;

                    $tokens[] = new Token(
                        id: $id,
                        text: $text,
                        line: $line,
                    );

                    // Advance our line counter for any newlines inside this token
                    // so the *next* single-char token after a multi-line string or
                    // comment gets an accurate estimate.
                    $newlineCount = substr_count($text, "\n");
                    if ($newlineCount > 0) {
                        $currentLine += $newlineCount;
                    }
                } else {
                    // Single-character punctuation token: no line info provided by PHP.
                    // Use the current tracked line as our best estimate.
                    $tokens[] = new Token(
                        id: -1,
                        text: $entry,
                        line: $currentLine,
                    );
                }
            }
        } catch (\Throwable $e) {
            // Ensure the tokenizer never propagates exceptions.
            $parseErrors[] = new ParseError(
                message: sprintf(
                    'Tokenization failed%s: %s',
                    $filePath !== '' ? " for {$filePath}" : '',
                    $e->getMessage(),
                ),
                line: 0,
                context: '',
            );
        }

        return TokenizeResult::create(
            tokens: $tokens,
            parseErrors: $parseErrors,
        );
    }

    /**
     * Count the number of lines in a source string.
     *
     * Returns the newline count plus one, matching the behaviour of PHP's
     * token_get_all() which uses 1-based line numbers where a string with no
     * newlines is entirely on line 1.
     *
     * @param string $source Raw PHP source code.
     * @return int Number of lines (always >= 1).
     */
    public function extractLineCount(string $source): int
    {
        return substr_count($source, "\n") + 1;
    }
}
