<?php

declare(strict_types=1);

namespace Wpma\Engine;

use Wpma\Cli\ScanTargetType;
use Wpma\Config\ScanConfig;

final readonly class ScanPlan
{
    public const FILE_DISCOVERY    = 'file_discovery';
    public const PATTERN_FILTERING = 'pattern_filtering';
    public const CORE_INTEGRITY    = 'core_integrity';
    public const PLUGIN_INTEGRITY  = 'plugin_integrity';
    public const MALWARE_ANALYSIS  = 'malware_analysis';

    /** @param list<string> $stages */
    public function __construct(private array $stages) {}

    public static function forConfig(ScanConfig $config): self
    {
        $stages = [self::FILE_DISCOVERY, self::PATTERN_FILTERING];

        if ($config->checkCore
            && in_array($config->targetType, [ScanTargetType::WORDPRESS_SITE, ScanTargetType::WORDPRESS_CORE], true)
        ) {
            $stages[] = self::CORE_INTEGRITY;
        }

        if (in_array(
            $config->targetType,
            [ScanTargetType::WORDPRESS_SITE, ScanTargetType::PLUGINS_DIRECTORY, ScanTargetType::SINGLE_PLUGIN],
            true
        )) {
            $stages[] = self::PLUGIN_INTEGRITY;
        }

        if (!$config->quickMode) {
            $stages[] = self::MALWARE_ANALYSIS;
        }

        return new self($stages);
    }

    /** @return list<string> */
    public function stages(): array
    {
        return $this->stages;
    }

    public function count(): int
    {
        return count($this->stages);
    }

    public function has(string $stage): bool
    {
        return in_array($stage, $this->stages, true);
    }

    public function indexOf(string $stage): ?int
    {
        $index = array_search($stage, $this->stages, true);

        return $index === false ? null : $index + 1;
    }
}
