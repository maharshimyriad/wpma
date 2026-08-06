<?php

declare(strict_types=1);

namespace Wpma\Models;

/**
 * DetectionCategory — the broad threat category a Finding belongs to.
 */
enum DetectionCategory: string
{
    case OBFUSCATION       = 'obfuscation';
    case EXECUTION         = 'execution';
    case NETWORK           = 'network';
    case PERSISTENCE       = 'persistence';
    case USER_INPUT        = 'user_input';
    case FILE_MANIPULATION = 'file_manipulation';
    case SEO_SPAM          = 'seo_spam';
    case REDIRECT          = 'redirect';
    case CREDENTIAL_STEAL  = 'credential_steal';
    case JS_INJECTION      = 'js_injection';
    case WEBSHELL          = 'webshell';
    case BACKDOOR          = 'backdoor';
    case CUSTOM            = 'custom';
    case INTEGRITY         = 'integrity';  // Plugin/theme file integrity violations
}
