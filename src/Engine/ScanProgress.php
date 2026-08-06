<?php

declare(strict_types=1);

namespace Wpma\Engine;

use Wpma\Config\ScanConfig;

final class ScanProgress
{
    /** @var callable(string): void */
    private $writer;
    private TerminalActivityIndicator $activity;
    private readonly bool $interactive;
    /** @var array<string, true> */
    private array $disabledStages = [];
    private float $lastAnalysisUpdateAt = 0.0;
    private int $lastAnalysisDone = 0;
    private bool $analysisLineActive = false;

    /** @param callable(string): void|null $writer */
    public function __construct(
        private readonly ScanConfig $config,
        private readonly ScanPlan $plan,
        ?callable $writer = null,
        ?bool $interactive = null,
    ) {
        $this->writer = $writer ?? static function (string $message): void {
            fwrite(STDERR, $message);
        };

        $this->interactive = $interactive ?? self::isInteractiveStdout();
        $this->activity = new TerminalActivityIndicator(
            enabled: $this->isEnabled(),
            interactive: $this->interactive,
            writer: $this->writer,
        );
    }

    public function isEnabled(): bool
    {
        return $this->config->showProgress;
    }

    public function beginFileDiscovery(): void
    {
        // File discovery is rendered on completion so runtime-dependent stage
        // removal can still produce contiguous numbering.
    }

    public function noteFileDiscoveryResult(int $fileCount): void
    {
        if ($fileCount === 0) {
            $this->disableStage(ScanPlan::PATTERN_FILTERING);
        }
    }

    public function completeFileDiscovery(int $fileCount): void
    {
        $this->noteFileDiscoveryResult($fileCount);

        $this->renderStage(ScanPlan::FILE_DISCOVERY, 'Indexing PHP files...');
        $this->line(sprintf('  %s    %d PHP files', $this->successMark(), $fileCount));
    }

    public function beginPatternFiltering(): void
    {
        $this->renderStage(ScanPlan::PATTERN_FILTERING, 'Pattern filtering...');
    }

    public function completePatternFiltering(int $selectedCount, int $totalCount): void
    {
        $this->line(sprintf(
            '  %s    %d suspicious candidate(s) identified from %d PHP file(s)',
            $this->successMark(),
            $selectedCount,
            $totalCount,
        ));
    }

    public function beginCoreIntegrity(): void
    {
        $this->renderStage(ScanPlan::CORE_INTEGRITY, 'Checking WordPress core integrity');
        $this->activity->start('Checking WordPress.org integrity');
    }

    public function finishCoreIntegrity(): void
    {
        $this->activity->stop();
    }

    public function beginPluginIntegrity(): void
    {
        $this->renderStage(ScanPlan::PLUGIN_INTEGRITY, 'Checking plugin integrity');
    }

    public function beginPluginCheck(int $current, int $total, string $slug): void
    {
        $this->activity->start(sprintf('[%d/%d] Checking %s', $current, $total, $slug));
    }

    public function finishPluginCheck(): void
    {
        $this->activity->stop();
    }

    public function completePluginIntegrity(int $checkedCount): void
    {
        $noun = $checkedCount === 1 ? 'plugin' : 'plugins';
        $this->line(sprintf('  %s    %d %s checked', $this->successMark(), $checkedCount, $noun));
    }

    public function beginMalwareAnalysis(): void
    {
        $this->renderStage(ScanPlan::MALWARE_ANALYSIS, 'Malware analysis');
    }

    public function updateMalwareProgress(int $done, int $total, string $file): void
    {
        if (!$this->isEnabled()) {
            return;
        }

        $now = microtime(true);
        $shouldUpdate = $done === $total
            || $done === 1
            || $done >= ($this->lastAnalysisDone + 50)
            || ($now - $this->lastAnalysisUpdateAt) >= 0.2;

        if (!$shouldUpdate) {
            return;
        }

        $this->lastAnalysisDone = $done;
        $this->lastAnalysisUpdateAt = $now;

        $name = basename($file);
        if (strlen($name) > 40) {
            $name = substr($name, 0, 37) . '...';
        }

        $pct = $total > 0 ? (int) round(($done / $total) * 100) : 0;
        $line = sprintf('     [%d/%d %d%%] %s', $done, $total, $pct, $name);

        if ($this->interactive) {
            ($this->writer)("\r{$line}" . str_repeat(' ', 20));
            $this->analysisLineActive = true;
            return;
        }

        ($this->writer)("{$line}\n");
    }

    public function completeMalwareAnalysis(): void
    {
        if (!$this->isEnabled()) {
            return;
        }

        if ($this->analysisLineActive) {
            ($this->writer)("\r" . str_repeat(' ', 120) . "\r");
            $this->analysisLineActive = false;
        }

        $this->line(sprintf('  %s    Analysis complete', $this->successMark()));
    }

    public function line(string $message): void
    {
        if (!$this->isEnabled()) {
            return;
        }

        $this->activity->stop();

        if ($this->analysisLineActive) {
            ($this->writer)("\r" . str_repeat(' ', 120) . "\r");
            $this->analysisLineActive = false;
        }

        ($this->writer)($message . "\n");
    }

    public function disableStage(string $stage): void
    {
        if ($this->plan->has($stage)) {
            $this->disabledStages[$stage] = true;
        }
    }

    private function renderStage(string $stage, string $label): void
    {
        if (!$this->isEnabled() || !$this->isVisibleStage($stage)) {
            return;
        }

        $index = $this->visibleIndexOf($stage);
        if ($index === null) {
            return;
        }

        $visibleCount = $this->visibleStageCount();
        $stagePrefix = $this->noColor()
            ? sprintf('  %d/%d', $index, $visibleCount)
            : sprintf("  \033[36m%d/%d\033[0m", $index, $visibleCount);

        $this->line(sprintf('%s  %s', $stagePrefix, $label));
    }

    private function isVisibleStage(string $stage): bool
    {
        return $this->plan->has($stage) && !isset($this->disabledStages[$stage]);
    }

    private function visibleStageCount(): int
    {
        return count($this->visibleStages());
    }

    private function visibleIndexOf(string $stage): ?int
    {
        $index = array_search($stage, $this->visibleStages(), true);

        return $index === false ? null : $index + 1;
    }

    /** @return list<string> */
    private function visibleStages(): array
    {
        return array_values(array_filter(
            $this->plan->stages(),
            fn (string $stage): bool => !isset($this->disabledStages[$stage])
        ));
    }

    private function successMark(): string
    {
        return $this->noColor() ? 'OK' : "\033[32m✔\033[0m";
    }

    private function noColor(): bool
    {
        return $this->config->noColor;
    }

    public static function isInteractiveStdout(): bool
    {
        if (function_exists('stream_isatty')) {
            return @stream_isatty(STDOUT);
        }

        if (function_exists('posix_isatty')) {
            return @posix_isatty(STDOUT);
        }

        return false;
    }
}
