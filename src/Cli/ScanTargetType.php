<?php

declare(strict_types=1);

namespace Wpma\Cli;

enum ScanTargetType: string
{
    case WORDPRESS_SITE    = 'WORDPRESS_SITE';
    case WORDPRESS_CORE    = 'WORDPRESS_CORE';
    case PLUGINS_DIRECTORY = 'PLUGINS_DIRECTORY';
    case SINGLE_PLUGIN     = 'SINGLE_PLUGIN';
    case THEMES_DIRECTORY  = 'THEMES_DIRECTORY';
    case SINGLE_THEME      = 'SINGLE_THEME';
    case UPLOADS_DIRECTORY = 'UPLOADS_DIRECTORY';
    case SINGLE_FILE       = 'SINGLE_FILE';
    case GENERIC_DIRECTORY = 'GENERIC_DIRECTORY';
    case UNKNOWN           = 'UNKNOWN';
}
