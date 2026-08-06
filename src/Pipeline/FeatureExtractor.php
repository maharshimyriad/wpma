<?php

declare(strict_types=1);

namespace Wpma\Pipeline;

use Wpma\Models\FileFeatures;
use Wpma\Models\Token;

/**
 * FeatureExtractor — computes higher-level features from the token stream
 * and raw source. Populates FileFeatures for use by detectors.
 */
class FeatureExtractor
{
    private const ENCODE_FUNCS = [
        'base64_decode', 'base64_encode', 'gzinflate', 'gzdecode',
        'gzuncompress', 'str_rot13', 'pack', 'unpack', 'hex2bin',
        'rawurldecode', 'urldecode', 'convert_uuencode', 'convert_uudecode',
    ];

    private const NETWORK_FUNCS = [
        'curl_init', 'curl_exec', 'curl_setopt', 'fsockopen',
        'stream_socket_client', 'file_get_contents', 'fopen',
        'socket_create', 'socket_connect', 'wp_remote_get', 'wp_remote_post',
    ];

    private const FILE_WRITE_FUNCS = [
        'file_put_contents', 'fwrite', 'fputs', 'file_put_contents',
        'move_uploaded_file', 'copy', 'rename',
    ];

    // Only these are genuine obfuscation indicators — NOT string concatenation
    private const REAL_OBFUSCATION_FUNCS = [
        'base64_decode', 'gzinflate', 'gzdecode', 'gzuncompress',
        'str_rot13', 'hex2bin', 'pack', 'convert_uuencode', 'convert_uudecode',
    ];

    // Dynamic dispatch is only suspicious when combined with other indicators
    private const DYNAMIC_DISPATCH_FUNCS = [
        'call_user_func', 'call_user_func_array', 'preg_replace_callback',
        'usort', 'array_map', 'array_filter', 'array_walk',
    ];

    private const USER_INPUT_VARS = [
        '$_POST', '$_GET', '$_REQUEST', '$_COOKIE', '$_SERVER', '$_FILES',
    ];

    /** @param Token[] $tokens */
    public function extract(array $tokens, string $rawContent): FileFeatures
    {
        $encodedBlobs         = [];
        $dynamicDispatchCalls = [];
        $userInputSources     = [];
        $networkCalls         = [];
        $fileWriteCalls       = [];

        $lowerContent = strtolower($rawContent);

        // Walk token stream
        foreach ($tokens as $token) {
            $text  = $token->text;
            $lower = strtolower(trim($text));

            if ($token->id === T_STRING || $token->id === T_CONSTANT_ENCAPSED_STRING) {
                if (in_array($lower, self::ENCODE_FUNCS, true)) {
                    // Check for large encoded blobs in string literals
                } elseif (in_array($lower, self::NETWORK_FUNCS, true)) {
                    $networkCalls[] = $text . ':' . $token->line;
                } elseif (in_array($lower, self::FILE_WRITE_FUNCS, true)) {
                    $fileWriteCalls[] = $text . ':' . $token->line;
                } elseif (in_array($lower, self::DYNAMIC_DISPATCH_FUNCS, true)) {
                    $dynamicDispatchCalls[] = $text . ':' . $token->line;
                }

                // Detect large base64 blobs in string literals
                // Must: be long enough, have +/ or = padding, and not be a plain alphabet/charset string
                if ($token->id === T_CONSTANT_ENCAPSED_STRING) {
                    $val = trim($text, '"\'');
                    if (strlen($val) > 50
                        && preg_match('/^[A-Za-z0-9+\/]{50,}={0,2}$/', $val)
                        && (str_contains($val, '+') || str_contains($val, '/') || str_ends_with($val, '='))
                        && !$this->isAlphabetString($val)
                    ) {
                        $encodedBlobs[] = substr($val, 0, 40) . '...(base64)';
                    }
                    // Hex blob: must be very long and contain no lowercase+uppercase mix (not a normal string)
                    if (strlen($val) > 100
                        && preg_match('/^[0-9a-fA-F]{100,}$/', $val)
                        && !$this->isVersionOrHashString($val)
                    ) {
                        $encodedBlobs[] = substr($val, 0, 40) . '...(hex)';
                    }
                }
            }

            if ($token->id === T_VARIABLE && in_array($text, self::USER_INPUT_VARS, true)) {
                $userInputSources[] = $text . ':' . $token->line;
            }
        }

    // Scan raw content for encoded blobs (catches heredoc/nowdoc)
        // Only flag base64 — pure hex strings are often SHA256 hashes in security plugins, not obfuscation
        if (preg_match_all('/[A-Za-z0-9+\/]{100,}={0,2}/', $rawContent, $m)) {
            foreach ($m[0] as $blob) {
                // Must have + or / to be actual base64 (not a hex hash or alphabet string)
                if ((str_contains($blob, '+') || str_contains($blob, '/'))
                    && !$this->isAlphabetString($blob)
                ) {
                    $encodedBlobs[] = substr($blob, 0, 40) . '...(base64-raw)';
                }
            }
        }

        $obfuscationScore = $this->computeObfuscationScore(
            $rawContent, $tokens, $encodedBlobs, $dynamicDispatchCalls
        );

        $entropyScore = $this->computeEntropyScore($rawContent);

        return new FileFeatures(
            encodedBlobs:         array_unique($encodedBlobs),
            dynamicDispatchCalls: $dynamicDispatchCalls,
            userInputSources:     array_unique($userInputSources),
            networkCalls:         $networkCalls,
            fileWriteCalls:       $fileWriteCalls,
            obfuscationScore:     $obfuscationScore,
            entropyScore:         $entropyScore,
        );
    }

    private function computeObfuscationScore(
        string $rawContent,
        array $tokens,
        array $encodedBlobs,
        array $dynamicDispatch,
    ): float {
        $score = 0.0;
        $indicators = [];

        // Only count genuine encoding/decoding functions found in executable code
        // BUT only increase obfuscation score if there are ALSO encoded blobs or eval
        // (base64_decode alone in a security plugin is legitimate — it decodes stored checksums)
        $obfuscFuncCount = 0;
        $hasEval = false;
        foreach ($tokens as $token) {
            if ($token->id === T_STRING) {
                $lower = strtolower($token->text);
                if (\in_array($lower, self::REAL_OBFUSCATION_FUNCS, true)) {
                    $obfuscFuncCount++;
                    $indicators[] = $lower;
                }
            }
            if ($token->id === T_EVAL) {
                $hasEval = true;
            }
        }

        // Obfuscation functions only score if combined with encoded blobs OR eval
        // A security plugin using base64_decode alone is NOT obfuscation
        if ($obfuscFuncCount > 0 && (!empty($encodedBlobs) || $hasEval)) {
            $score += min($obfuscFuncCount * 0.2, 0.5);
        } elseif ($obfuscFuncCount >= 5) {
            // 5+ encoding funcs even without blobs is suspicious (3 was too low for security plugins)
            $score += min(($obfuscFuncCount - 4) * 0.1, 0.3);
        }

        // Large base64 blobs (must have +/ chars to distinguish from hex hashes)
        if (!empty($encodedBlobs)) {
            $score += min(count($encodedBlobs) * 0.15, 0.3);
            $indicators[] = 'large-encoded-blob';
        }

        // eval() in executable context — already counted above via T_EVAL token
        if ($hasEval) {
            $score += 0.3;
            $indicators[] = 'eval';
        }

        // Variable-variable dispatch ($$var) — genuine obfuscation
        if (preg_match('/\$\$[a-zA-Z_]\w*/', $rawContent)) {
            $score += 0.15;
            $indicators[] = 'variable-variable';
        }

        // High ratio of hex escape sequences (\x41\x42...) — genuine obfuscation
        $hexEscapes = preg_match_all('/\\\\x[0-9a-fA-F]{2}/', $rawContent);
        if ($hexEscapes > 20) {
            $score += min($hexEscapes * 0.005, 0.25);
            $indicators[] = 'hex-escape-sequences';
        }

        // chr() chains — used to build strings character by character
        $chrCount = substr_count(strtolower($rawContent), 'chr(');
        if ($chrCount > 10) {
            $score += min($chrCount * 0.01, 0.2);
            $indicators[] = 'chr-chains';
        }

        // Multiple chained decoding (e.g. gzinflate(base64_decode(...))) — already covered above

        return round(min($score, 1.0), 4);
    }

    private function computeEntropyScore(string $rawContent): float
    {
        if (empty($rawContent)) {
            return 0.0;
        }

        $len   = strlen($rawContent);
        $freq  = array_count_values(str_split($rawContent));
        $entropy = 0.0;

        foreach ($freq as $count) {
            $p = $count / $len;
            $entropy -= $p * log($p, 2);
        }

        // Max entropy for byte data is 8 bits; normalise to [0,1]
        return round(min($entropy / 8.0, 1.0), 4);
    }

    /**
     * Returns true if the string is just a character set / alphabet
     * e.g. 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
     * These are used in random token generation and should NOT be flagged as base64.
     */
    private function isAlphabetString(string $val): bool
    {
        // Check if characters are mostly sequential (alphabet-like)
        $chars = str_split($val);
        $unique = array_unique($chars);
        // If > 80% of chars are unique and length matches alphabet sizes, it's a charset
        $uniqueRatio = count($unique) / strlen($val);
        if ($uniqueRatio > 0.8 && strlen($val) <= 128) {
            return true;
        }
        return false;
    }

    /**
     * Returns true if the string looks like a standard hash or version string.
     * These should NOT be flagged as hex blobs.
     */
    private function isVersionOrHashString(string $val): bool
    {
        $len = strlen($val);
        // Standard hash lengths: MD5=32, SHA1=40, SHA256=64, SHA512=128
        return \in_array($len, [32, 40, 64, 128], true);
    }
}
