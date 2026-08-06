<?php

declare(strict_types=1);

namespace Wpma\Models;

/**
 * OutputFormat — report output format requested by the user.
 */
enum OutputFormat: string
{
    case TEXT = 'text';
    case JSON = 'json';
    case HTML = 'html';
}
