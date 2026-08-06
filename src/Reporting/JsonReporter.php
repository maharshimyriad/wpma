<?php

declare(strict_types=1);

namespace Wpma\Reporting;

use Wpma\Models\ScanReport;

class JsonReporter implements ReporterInterface
{
    public function render(ScanReport $report): string
    {
        return json_encode($report->toArray(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
}
