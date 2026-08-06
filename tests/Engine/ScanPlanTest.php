<?php

declare(strict_types=1);

namespace Wpma\Tests\Engine;

use PHPUnit\Framework\TestCase;
use Wpma\Cli\ScanTargetType;
use Wpma\Config\ScanConfig;
use Wpma\Engine\ScanPlan;

final class ScanPlanTest extends TestCase
{
    public function testWordPressSitePlanIncludesCorePluginAndMalware(): void
    {
        $plan = ScanPlan::forConfig(new ScanConfig('/wp', targetType: ScanTargetType::WORDPRESS_SITE));

        $this->assertSame([
            ScanPlan::FILE_DISCOVERY,
            ScanPlan::PATTERN_FILTERING,
            ScanPlan::CORE_INTEGRITY,
            ScanPlan::PLUGIN_INTEGRITY,
            ScanPlan::MALWARE_ANALYSIS,
        ], $plan->stages());
    }

    public function testPluginsDirectoryPlanIncludesPluginButNotCore(): void
    {
        $plan = ScanPlan::forConfig(new ScanConfig('/wp/wp-content/plugins', targetType: ScanTargetType::PLUGINS_DIRECTORY));

        $this->assertTrue($plan->has(ScanPlan::PLUGIN_INTEGRITY));
        $this->assertTrue($plan->has(ScanPlan::MALWARE_ANALYSIS));
        $this->assertFalse($plan->has(ScanPlan::CORE_INTEGRITY));
    }

    public function testSinglePluginPlanDoesNotIncludeCore(): void
    {
        $plan = ScanPlan::forConfig(new ScanConfig('/wp/wp-content/plugins/wordfence', targetType: ScanTargetType::SINGLE_PLUGIN));

        $this->assertTrue($plan->has(ScanPlan::PLUGIN_INTEGRITY));
        $this->assertFalse($plan->has(ScanPlan::CORE_INTEGRITY));
    }

    public function testSingleThemePlanDoesNotIncludeCoreOrPluginIntegrity(): void
    {
        $plan = ScanPlan::forConfig(new ScanConfig('/wp/wp-content/themes/astra', targetType: ScanTargetType::SINGLE_THEME));

        $this->assertFalse($plan->has(ScanPlan::CORE_INTEGRITY));
        $this->assertFalse($plan->has(ScanPlan::PLUGIN_INTEGRITY));
        $this->assertTrue($plan->has(ScanPlan::MALWARE_ANALYSIS));
    }

    public function testUploadsDirectoryPlanOnlyIncludesMalwareStageBeyondDiscovery(): void
    {
        $plan = ScanPlan::forConfig(new ScanConfig('/wp/wp-content/uploads', targetType: ScanTargetType::UPLOADS_DIRECTORY));

        $this->assertSame([
            ScanPlan::FILE_DISCOVERY,
            ScanPlan::PATTERN_FILTERING,
            ScanPlan::MALWARE_ANALYSIS,
        ], $plan->stages());
    }

    public function testSingleFilePlanIncludesMalwareAnalysis(): void
    {
        $plan = ScanPlan::forConfig(new ScanConfig('/wp/wp-config.php', targetType: ScanTargetType::SINGLE_FILE));

        $this->assertTrue($plan->has(ScanPlan::MALWARE_ANALYSIS));
        $this->assertFalse($plan->has(ScanPlan::CORE_INTEGRITY));
        $this->assertFalse($plan->has(ScanPlan::PLUGIN_INTEGRITY));
    }

    public function testGenericDirectoryPlanIncludesMalwareAnalysisOnlyBeyondDiscovery(): void
    {
        $plan = ScanPlan::forConfig(new ScanConfig('/tmp/generic', targetType: ScanTargetType::GENERIC_DIRECTORY));

        $this->assertSame([
            ScanPlan::FILE_DISCOVERY,
            ScanPlan::PATTERN_FILTERING,
            ScanPlan::MALWARE_ANALYSIS,
        ], $plan->stages());
    }

    public function testQuickModeOmitsMalwareStage(): void
    {
        $plan = ScanPlan::forConfig(new ScanConfig(
            '/wp',
            quickMode: true,
            targetType: ScanTargetType::WORDPRESS_SITE,
        ));

        $this->assertSame([
            ScanPlan::FILE_DISCOVERY,
            ScanPlan::PATTERN_FILTERING,
            ScanPlan::CORE_INTEGRITY,
            ScanPlan::PLUGIN_INTEGRITY,
        ], $plan->stages());
    }

    public function testNoCoreFlagRemovesCoreIntegrityStage(): void
    {
        $plan = ScanPlan::forConfig(new ScanConfig(
            '/wp',
            checkCore: false,
            targetType: ScanTargetType::WORDPRESS_SITE,
        ));

        $this->assertFalse($plan->has(ScanPlan::CORE_INTEGRITY));
        $this->assertTrue($plan->has(ScanPlan::PLUGIN_INTEGRITY));
        $this->assertTrue($plan->has(ScanPlan::MALWARE_ANALYSIS));
    }

    public function testPlanSupportsMsysAndWindowsStyleTargets(): void
    {
        $msysPlan = ScanPlan::forConfig(new ScanConfig(
            '/c/xampp/htdocs/public_html/wp-content/plugins/wordfence',
            targetType: ScanTargetType::SINGLE_PLUGIN,
        ));
        $windowsPlan = ScanPlan::forConfig(new ScanConfig(
            'C:\\xampp\\htdocs\\public_html\\wp-content\\plugins\\wordfence',
            targetType: ScanTargetType::SINGLE_PLUGIN,
        ));

        $this->assertSame($msysPlan->stages(), $windowsPlan->stages());
        $this->assertSame([
            ScanPlan::FILE_DISCOVERY,
            ScanPlan::PATTERN_FILTERING,
            ScanPlan::PLUGIN_INTEGRITY,
            ScanPlan::MALWARE_ANALYSIS,
        ], $windowsPlan->stages());
    }
}
