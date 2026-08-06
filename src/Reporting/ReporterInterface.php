<?php

declare(strict_types=1);

namespace Wpma\Reporting;

use Wpma\Models\ScanReport;

interface ReporterInterface
{
    public function render(ScanReport $report): string;
}
