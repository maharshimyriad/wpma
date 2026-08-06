<?php

declare(strict_types=1);

namespace Wpma\Pipeline;

use Wpma\Models\ExtractedString;
use Wpma\Models\FunctionCall;
use Wpma\Models\IncludeStatement;
use Wpma\Models\Token;
use Wpma\Models\VariableAssignment;
use Wpma\Models\VariableRef;

/**
 * TokenExtractor — walks a flat PHP token stream and extracts structured features.
 *
 * Stateless: a single instance may be reused across many token streams.
 */
class TokenExtractor
{
    /** PHP superglobals that carry untrusted user-supplied data. */
    private const USER_INPUT_VARS = [
        '$_POST',
        '$_GET',
        '$_REQUEST',
        '$_COOKIE',
        '$_SERVER',
        '$_FILES',
    ];

    /** Function names that imply dynamic dispatch. */
    private const DYNAMIC_DISPATCH_FUNCS = [
        'call_user_func',
        'call_user_func_array',
    ];

    /** PHP include/require token ids. */
    private const IMPORT_TOKEN_IDS = [
        \T_INCLUDE,
        \T_INCLUDE_ONCE,
        \T_REQUIRE,
        \T_REQUIRE_ONCE,
    ];

    /**
     * Token ids for PHP language constructs that syntactically look like function
     * calls (i.e. they are followed by a parenthesised argument list) and are
     * relevant to malware analysis.
     */
    private const CALL_LIKE_TOKEN_IDS = [
        \T_EVAL,   // eval(...)
        \T_ISSET,  // isset(...)
        \T_UNSET,  // unset(...)
        \T_EMPTY,  // empty(...)
        \T_LIST,   // list(...)
        \T_ARRAY,  // array(...)
        \T_PRINT,  // print(...)
    ];

    /**
     * Extract structured features from a flat array of Token objects.
     *
     * @param Token[] $tokens
     */
    public function extract(array $tokens): TokenExtractorResult
    {
        /** @var FunctionCall[]     $functionCalls */
        $functionCalls = [];
        /** @var ExtractedString[]  $strings */
        $strings = [];
        /** @var VariableRef[]      $variables */
        $variables = [];
        /** @var IncludeStatement[] $imports */
        $imports = [];
        /** @var VariableAssignment[] $assignments */
        $assignments = [];

        $count = count($tokens);

        for ($i = 0; $i < $count; $i++) {
            $token = $tokens[$i];

            // ── FUNCTION CALLS ────────────────────────────────────────────────
            // Match T_STRING (named function), T_VARIABLE ($fn()), or language
            // constructs that accept a parenthesised argument list (T_EVAL, etc.)
            if ($token->id === \T_STRING
                || $token->id === \T_VARIABLE
                || in_array($token->id, self::CALL_LIKE_TOKEN_IDS, true)
            ) {
                $nextIdx = $this->nextNonWhitespace($tokens, $i + 1);

                if ($nextIdx !== null && $tokens[$nextIdx]->text === '(') {
                    $isDynamic = $token->id === \T_VARIABLE
                        || in_array($token->text, self::DYNAMIC_DISPATCH_FUNCS, true);

                    [$args, $endIdx] = $this->collectArgs($tokens, $nextIdx + 1);

                    $functionCalls[] = new FunctionCall(
                        name: $token->text,
                        args: $args,
                        line: $token->line,
                        isDynamic: $isDynamic,
                    );

                    // Advance past the closing ')' so we don't re-process tokens
                    // that were already consumed as arguments.
                    $i = $endIdx;
                    continue;
                }
            }

            // ── STRINGS ───────────────────────────────────────────────────────
            if ($token->id === \T_CONSTANT_ENCAPSED_STRING
                || $token->id === \T_ENCAPSED_AND_WHITESPACE
            ) {
                $value = $this->stripStringQuotes($token->text);
                $isEncoded = $this->looksEncoded($value);

                $strings[] = new ExtractedString(
                    value: $value,
                    line: $token->line,
                    isEncoded: $isEncoded,
                );
                continue;
            }

            // ── VARIABLES ─────────────────────────────────────────────────────
            if ($token->id === \T_VARIABLE) {
                $nextIdx = $this->nextNonWhitespace($tokens, $i + 1);
                if ($nextIdx !== null && ($tokens[$nextIdx]->text === '=' || $tokens[$nextIdx]->text === '.=')) {
                    $operator = $tokens[$nextIdx]->text;
                    [$expression, $endIdx] = $this->collectAssignmentExpression($tokens, $nextIdx + 1);
                    $assignments[] = new VariableAssignment(
                        variableName: $token->text,
                        line: $token->line,
                        expression: $operator === '.=' ? $token->text . ' . ' . $expression : $expression,
                        functionNames: $this->extractFunctionNamesFromExpression($expression),
                        usesUserInput: $this->expressionUsesUserInput($expression),
                    );
                }

                // Note: T_VARIABLE followed by '(' was already handled above as a
                // function call, so this branch only fires when the next non-ws
                // token is NOT '(' (we already 'continue'd in the call branch).
                // The continue above exits this loop iteration, so we only reach
                // here when the variable is NOT immediately followed by '('.
                $isUserInput = in_array($token->text, self::USER_INPUT_VARS, true);

                $variables[] = new VariableRef(
                    name: $token->text,
                    line: $token->line,
                    isUserInput: $isUserInput,
                );
                continue;
            }

            // ── IMPORTS ───────────────────────────────────────────────────────
            if (in_array($token->id, self::IMPORT_TOKEN_IDS, true)) {
                $keyword = strtolower(trim($token->text));
                [$pathExpr, $isDynamic, $endIdx] = $this->collectImportPath($tokens, $i + 1);

                $imports[] = new IncludeStatement(
                    keyword: $keyword,
                    path: $pathExpr,
                    line: $token->line,
                    isDynamic: $isDynamic,
                );

                $i = $endIdx;
                continue;
            }
        }

        return new TokenExtractorResult(
            functionCalls: $functionCalls,
            strings: $strings,
            variables: $variables,
            imports: $imports,
            assignments: $assignments,
        );
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /**
     * Return the index of the next non-whitespace token at or after $from,
     * or null if none exists.
     *
     * @param Token[] $tokens
     */
    private function nextNonWhitespace(array $tokens, int $from): ?int
    {
        $count = count($tokens);
        for ($i = $from; $i < $count; $i++) {
            if ($tokens[$i]->id !== \T_WHITESPACE) {
                return $i;
            }
        }
        return null;
    }

    /**
     * Collect function arguments starting right after the opening '('.
     *
     * Handles nested parentheses, brackets, and braces so commas inside nested
     * structures (function calls, arrays, closures, etc.) do not split the
     * outer function's arguments.
     * Returns [string[] $args, int $closingParenIndex].
     *
     * Each argument is the trimmed concatenation of its token texts.
     *
     * @param  Token[]               $tokens
     * @param  int                   $from   Index of the first token inside the '('
     * @return array{0: string[], 1: int}
     */
    private function collectArgs(array $tokens, int $from): array
    {
        $args = [];
        $parenDepth = 1;   // We are already inside the opening '('
        $bracketDepth = 0;
        $braceDepth = 0;
        $buf = '';
        $count = count($tokens);

        for ($i = $from; $i < $count; $i++) {
            $t = $tokens[$i];

            if ($t->text === '(') {
                $parenDepth++;
                $buf .= $t->text;
                continue;
            }

            if ($t->text === ')') {
                $parenDepth--;
                if ($parenDepth === 0 && $bracketDepth === 0 && $braceDepth === 0) {
                    // Closing paren of the outermost call — flush last arg.
                    $trimmed = trim($buf);
                    if ($trimmed !== '') {
                        $args[] = $trimmed;
                    }
                    return [$args, $i];
                }
                $buf .= $t->text;
                continue;
            }

            if ($t->text === '[') {
                $bracketDepth++;
                $buf .= $t->text;
                continue;
            }

            if ($t->text === ']') {
                $bracketDepth = max(0, $bracketDepth - 1);
                $buf .= $t->text;
                continue;
            }

            if ($t->text === '{') {
                $braceDepth++;
                $buf .= $t->text;
                continue;
            }

            if ($t->text === '}') {
                $braceDepth = max(0, $braceDepth - 1);
                $buf .= $t->text;
                continue;
            }

            // Comma at the outermost call depth separates arguments.
            if ($t->text === ',' && $parenDepth === 1 && $bracketDepth === 0 && $braceDepth === 0) {
                $trimmed = trim($buf);
                if ($trimmed !== '') {
                    $args[] = $trimmed;
                }
                $buf = '';
                continue;
            }

            $buf .= $t->text;
        }

        // If we exhausted tokens without finding the closing paren (malformed source),
        // flush whatever we have and report the last token index.
        $trimmed = trim($buf);
        if ($trimmed !== '') {
            $args[] = $trimmed;
        }
        return [$args, $count - 1];
    }

    /**
     * Collect an import path expression from $from up to (but not including) the
     * terminating ';'.
     *
     * Returns [string $pathExpr, bool $isDynamic, int $lastConsumedIndex].
     *
     * @param  Token[]                        $tokens
     * @param  int                            $from
     * @return array{0: string, 1: bool, 2: int}
     */
    private function collectImportPath(array $tokens, int $from): array
    {
        $buf       = '';
        $isDynamic = false;
        $count     = count($tokens);

        for ($i = $from; $i < $count; $i++) {
            $t = $tokens[$i];

            if ($t->text === ';') {
                return [trim($buf), $isDynamic, $i];
            }

            if ($t->id === \T_VARIABLE) {
                $isDynamic = true;
            }

            $buf .= $t->text;
        }

        // Malformed — no semicolon found.
        return [trim($buf), $isDynamic, $count - 1];
    }

    /**
     * Collect a simple assignment expression from the token after '=' up to the
     * terminating ';' at the current nesting depth.
     *
     * @param Token[] $tokens
     * @return array{0: string, 1: int}
     */
    private function collectAssignmentExpression(array $tokens, int $from): array
    {
        $buf = '';
        $parenDepth = 0;
        $bracketDepth = 0;
        $braceDepth = 0;
        $count = count($tokens);

        for ($i = $from; $i < $count; $i++) {
            $t = $tokens[$i];

            if ($t->text === '(') {
                $parenDepth++;
            } elseif ($t->text === ')') {
                $parenDepth = max(0, $parenDepth - 1);
            } elseif ($t->text === '[') {
                $bracketDepth++;
            } elseif ($t->text === ']') {
                $bracketDepth = max(0, $bracketDepth - 1);
            } elseif ($t->text === '{') {
                $braceDepth++;
            } elseif ($t->text === '}') {
                $braceDepth = max(0, $braceDepth - 1);
            } elseif ($t->text === ';' && $parenDepth === 0 && $bracketDepth === 0 && $braceDepth === 0) {
                return [trim($buf), $i];
            }

            $buf .= $t->text;
        }

        return [trim($buf), $count - 1];
    }

    /**
     * @return string[]
     */
    private function extractFunctionNamesFromExpression(string $expression): array
    {
        if ($expression === '') {
            return [];
        }

        preg_match_all('/\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/', $expression, $matches);
        return array_values(array_unique(array_map('strtolower', $matches[1] ?? [])));
    }

    private function expressionUsesUserInput(string $expression): bool
    {
        return preg_match('/\$_(POST|GET|REQUEST|COOKIE|SERVER|FILES)\b/', $expression) === 1;
    }

    /**
     * Strip surrounding quotes from a T_CONSTANT_ENCAPSED_STRING value.
     *
     * PHP returns single-quoted strings as `'value'` and double-quoted as `"value"`.
     * For T_ENCAPSED_AND_WHITESPACE (inside double-quoted strings) there are no
     * surrounding quotes; return as-is.
     */
    private function stripStringQuotes(string $raw): string
    {
        if (strlen($raw) >= 2) {
            $first = $raw[0];
            $last  = $raw[strlen($raw) - 1];

            if (($first === "'" && $last === "'")
                || ($first === '"' && $last === '"')
            ) {
                return substr($raw, 1, -1);
            }
        }
        return $raw;
    }

    /**
     * Heuristically decide whether a string value looks like an encoded payload.
     *
     * Two checks (either triggers isEncoded = true):
     *  1. Base64: 20+ chars of [A-Za-z0-9+/] optionally padded with '='.
     *  2. Hex blob: >100 chars composed entirely of hex digits.
     */
    private function looksEncoded(string $value): bool
    {
        // Base64 check
        if (preg_match('/^[A-Za-z0-9+\/]{20,}={0,2}$/', $value) === 1) {
            return true;
        }

        // Hex blob check
        if (strlen($value) > 100 && preg_match('/^[0-9a-fA-F]+$/', $value) === 1) {
            return true;
        }

        return false;
    }
}
