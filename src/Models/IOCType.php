<?php

declare(strict_types=1);

namespace Wpma\Models;

/**
 * IOCType — the kind of Indicator of Compromise extracted from a file.
 */
enum IOCType: string
{
    case URL              = 'url';
    case DOMAIN           = 'domain';
    case IP               = 'ip';
    case EMAIL            = 'email';
    case TELEGRAM_TOKEN   = 'telegram_token';
    case DISCORD_WEBHOOK  = 'discord_webhook';
    case JWT              = 'jwt';
    case BASE64_BLOB      = 'base64_blob';
    case HEX_BLOB         = 'hex_blob';
    case FILE_HASH        = 'file_hash';
}
