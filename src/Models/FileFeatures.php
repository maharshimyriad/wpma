<?php

declare(strict_types=1);

namespace Wpma\Models;

/**
 * FileFeatures — higher-level features extracted from a file by the FeatureExtractor.
 *
 * All array properties hold string values (matched patterns or evidence snippets).
 * Scores are floats in the range [0.0, 1.0].
 */
readonly class FileFeatures
{
    /**
     * @param array  $encodedBlobs          String evidence of base64, hex, or similarly
     *                                      encoded blobs found in the file.
     * @param array  $dynamicDispatchCalls  Evidence of dynamic function dispatch patterns
     *                                      (variable functions, call_user_func, etc.).
     * @param array  $userInputSources      Evidence of user-supplied superglobal access
     *                                      ($_POST, $_GET, $_REQUEST, $_COOKIE, $_SERVER,
     *                                      $_FILES).
     * @param array  $networkCalls          Evidence of outbound network operations
     *                                      (curl, fsockopen, file_get_contents with URL,
     *                                      etc.).
     * @param array  $fileWriteCalls        Evidence of filesystem write operations
     *                                      (file_put_contents, fwrite, etc.).
     * @param float  $obfuscationScore      A score in [0.0, 1.0] reflecting the degree of
     *                                      obfuscation detected in the file.
     *                                      0.0 = no obfuscation indicators,
     *                                      1.0 = highly obfuscated.
     * @param float  $entropyScore          A score in [0.0, 1.0] reflecting the Shannon
     *                                      entropy of the file's content, normalised to
     *                                      the [0.0, 1.0] range.
     *                                      High entropy often indicates encrypted or
     *                                      compressed payloads.
     * @param array  $taintPaths            Evidence of taint paths from user-supplied input
     *                                      to dangerous sinks, populated during intra-file
     *                                      taint analysis (Phase 4).
     */
    public function __construct(
        public array $encodedBlobs         = [],
        public array $dynamicDispatchCalls = [],
        public array $userInputSources     = [],
        public array $networkCalls         = [],
        public array $fileWriteCalls       = [],
        public float $obfuscationScore     = 0.0,
        public float $entropyScore         = 0.0,
        public array $taintPaths           = [],
    ) {}
}
