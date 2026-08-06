<?php

declare(strict_types=1);

namespace Wpma\Cli;

final class ScanTargetResolver
{
    /** @param array<string, mixed> $options */
    public static function resolve(?string $target, array $options = []): DetectedScanTarget
    {
        $requestedPath = self::normalizePath($target ?? (getcwd() ?: '.'));

        $override = self::resolveExplicitOverride($options);
        if ($override instanceof DetectedScanTarget) {
            return $override;
        }

        if (!file_exists($requestedPath)) {
            return self::invalid(
                $requestedPath,
                sprintf('Target does not exist: %s', $requestedPath),
                $override !== null
            );
        }

        if ($override !== null) {
            return match ($override) {
                'full-site' => self::resolveFullSiteOverride($requestedPath),
                'core'      => self::resolveCoreOverride($requestedPath),
                'plugins'   => self::resolvePluginsOverride($requestedPath),
                'themes'    => self::resolveThemesOverride($requestedPath),
                'file'      => self::resolveFileOverride($requestedPath),
                default     => self::invalid($requestedPath, sprintf('Unsupported scan override: %s', $override), true),
            };
        }

        return self::autoDetect($requestedPath);
    }

    /** @param array<string, mixed> $options */
    private static function resolveExplicitOverride(array $options): string|DetectedScanTarget|null
    {
        $map = [
            'full-site' => !empty($options['full-site']),
            'core'      => !empty($options['core']),
            'plugins'   => !empty($options['plugins']),
            'themes'    => !empty($options['themes']),
            'file'      => !empty($options['file']),
        ];

        $enabled = array_keys(array_filter($map, static fn (bool $enabled): bool => $enabled));

        if (count($enabled) > 1) {
            return self::invalid(
                self::normalizePath(getcwd() ?: '.'),
                'Only one of --full-site, --core, --plugins, --themes, or --file may be used at a time.',
                true
            );
        }

        return $enabled[0] ?? null;
    }

    private static function autoDetect(string $path): DetectedScanTarget
    {
        if (is_file($path)) {
            return new DetectedScanTarget($path, $path, ScanTargetType::SINGLE_FILE, 'Single File');
        }

        if (self::isWordPressSite($path)) {
            return new DetectedScanTarget($path, $path, ScanTargetType::WORDPRESS_SITE, 'Full Site');
        }

        if (self::isPluginsDirectory($path)) {
            return new DetectedScanTarget($path, $path, ScanTargetType::PLUGINS_DIRECTORY, 'Plugins');
        }

        if (self::isSinglePlugin($path)) {
            return new DetectedScanTarget($path, $path, ScanTargetType::SINGLE_PLUGIN, 'Plugin', basename($path));
        }

        if (self::isThemesDirectory($path)) {
            return new DetectedScanTarget($path, $path, ScanTargetType::THEMES_DIRECTORY, 'Themes');
        }

        if (self::isSingleTheme($path)) {
            return new DetectedScanTarget($path, $path, ScanTargetType::SINGLE_THEME, 'Theme', basename($path));
        }

        if (self::isUploadsDirectory($path)) {
            return new DetectedScanTarget($path, $path, ScanTargetType::UPLOADS_DIRECTORY, 'Uploads');
        }

        if (self::isWordPressCoreTarget($path)) {
            return new DetectedScanTarget($path, $path, ScanTargetType::WORDPRESS_CORE, 'Core');
        }

        if (is_dir($path)) {
            return new DetectedScanTarget($path, $path, ScanTargetType::GENERIC_DIRECTORY, 'Directory');
        }

        return self::invalid($path, sprintf('Unable to determine how to scan target: %s', $path), false);
    }

    private static function resolveFullSiteOverride(string $path): DetectedScanTarget
    {
        $siteRoot = self::findWordPressSiteRoot($path);

        if ($siteRoot === null) {
            return self::invalid(
                $path,
                sprintf('WordPress site root could not be found for --full-site: %s', $path),
                true
            );
        }

        return new DetectedScanTarget($path, $siteRoot, ScanTargetType::WORDPRESS_SITE, 'Full Site', usedExplicitOverride: true);
    }

    private static function resolveCoreOverride(string $path): DetectedScanTarget
    {
        if (self::isWordPressCoreTarget($path)) {
            return new DetectedScanTarget($path, $path, ScanTargetType::WORDPRESS_CORE, 'Core', usedExplicitOverride: true);
        }

        $siteRoot = self::findWordPressSiteRoot($path);
        if ($siteRoot !== null && self::hasWordPressCoreMarkers($siteRoot)) {
            return new DetectedScanTarget($path, $siteRoot, ScanTargetType::WORDPRESS_CORE, 'Core', usedExplicitOverride: true);
        }

        return self::invalid(
            $path,
            sprintf('WordPress core directories (wp-admin and wp-includes) could not be found for --core: %s', $path),
            true
        );
    }

    private static function resolvePluginsOverride(string $path): DetectedScanTarget
    {
        $pluginsDir = self::locatePluginsDirectory($path);

        if ($pluginsDir === null) {
            return self::invalid(
                $path,
                sprintf('wp-content/plugins could not be found for --plugins: %s', $path),
                true
            );
        }

        return new DetectedScanTarget($path, $pluginsDir, ScanTargetType::PLUGINS_DIRECTORY, 'Plugins', usedExplicitOverride: true);
    }

    private static function resolveThemesOverride(string $path): DetectedScanTarget
    {
        $themesDir = self::locateThemesDirectory($path);

        if ($themesDir === null) {
            return self::invalid(
                $path,
                sprintf('wp-content/themes could not be found for --themes: %s', $path),
                true
            );
        }

        return new DetectedScanTarget($path, $themesDir, ScanTargetType::THEMES_DIRECTORY, 'Themes', usedExplicitOverride: true);
    }

    private static function resolveFileOverride(string $path): DetectedScanTarget
    {
        if (!is_file($path)) {
            return self::invalid(
                $path,
                sprintf('--file requires a file target, but a directory was provided: %s', $path),
                true
            );
        }

        return new DetectedScanTarget($path, $path, ScanTargetType::SINGLE_FILE, 'Single File', usedExplicitOverride: true);
    }

    private static function locatePluginsDirectory(string $path): ?string
    {
        if (self::isPluginsDirectory($path)) {
            return $path;
        }

        if (self::isSinglePlugin($path)) {
            return dirname($path);
        }

        $siteRoot = self::findWordPressSiteRoot($path);
        if ($siteRoot === null) {
            return null;
        }

        $pluginsDir = $siteRoot . DIRECTORY_SEPARATOR . 'wp-content' . DIRECTORY_SEPARATOR . 'plugins';

        return is_dir($pluginsDir) ? self::normalizePath($pluginsDir) : null;
    }

    private static function locateThemesDirectory(string $path): ?string
    {
        if (self::isThemesDirectory($path)) {
            return $path;
        }

        if (self::isSingleTheme($path)) {
            return dirname($path);
        }

        $siteRoot = self::findWordPressSiteRoot($path);
        if ($siteRoot === null) {
            return null;
        }

        $themesDir = $siteRoot . DIRECTORY_SEPARATOR . 'wp-content' . DIRECTORY_SEPARATOR . 'themes';

        return is_dir($themesDir) ? self::normalizePath($themesDir) : null;
    }

    private static function findWordPressSiteRoot(string $path): ?string
    {
        $current = is_dir($path) ? $path : dirname($path);

        while (true) {
            if (self::isWordPressSite($current)) {
                return self::normalizePath($current);
            }

            $parent = dirname($current);
            if ($parent === $current) {
                break;
            }

            $current = $parent;
        }

        return null;
    }

    private static function isWordPressSite(string $path): bool
    {
        return is_dir($path)
            && is_file($path . DIRECTORY_SEPARATOR . 'wp-config.php')
            && is_dir($path . DIRECTORY_SEPARATOR . 'wp-admin')
            && is_dir($path . DIRECTORY_SEPARATOR . 'wp-includes')
            && is_dir($path . DIRECTORY_SEPARATOR . 'wp-content');
    }

    private static function hasWordPressCoreMarkers(string $path): bool
    {
        return is_dir($path)
            && is_dir($path . DIRECTORY_SEPARATOR . 'wp-admin')
            && is_dir($path . DIRECTORY_SEPARATOR . 'wp-includes');
    }

    private static function isWordPressCoreTarget(string $path): bool
    {
        if (!is_dir($path)) {
            return false;
        }

        if (self::hasWordPressCoreMarkers($path) && !self::isWordPressSite($path)) {
            return true;
        }

        $base = basename($path);
        if (!in_array($base, ['wp-admin', 'wp-includes'], true)) {
            return false;
        }

        $sibling = $base === 'wp-admin' ? 'wp-includes' : 'wp-admin';

        return is_dir(dirname($path) . DIRECTORY_SEPARATOR . $sibling);
    }

    private static function isPluginsDirectory(string $path): bool
    {
        return is_dir($path)
            && basename($path) === 'plugins'
            && basename(dirname($path)) === 'wp-content';
    }

    private static function isSinglePlugin(string $path): bool
    {
        return is_dir($path) && self::isPluginsDirectory(dirname($path));
    }

    private static function isThemesDirectory(string $path): bool
    {
        return is_dir($path)
            && basename($path) === 'themes'
            && basename(dirname($path)) === 'wp-content';
    }

    private static function isSingleTheme(string $path): bool
    {
        return is_dir($path) && self::isThemesDirectory(dirname($path));
    }

    private static function isUploadsDirectory(string $path): bool
    {
        if (!is_dir($path)) {
            return false;
        }

        $normalized = str_replace('\\', '/', self::normalizePath($path));

        return preg_match('#(?:^|/)wp-content/uploads(?:/|$)#', $normalized) === 1;
    }

    private static function invalid(string $requestedPath, string $message, bool $usedExplicitOverride): DetectedScanTarget
    {
        return new DetectedScanTarget(
            requestedPath: $requestedPath,
            resolvedPath: null,
            targetType: ScanTargetType::UNKNOWN,
            scanMode: 'Unknown',
            validationError: $message,
            usedExplicitOverride: $usedExplicitOverride,
        );
    }

    private static function normalizePath(string $path): string
    {
        $resolved = realpath($path);

        return $resolved !== false ? $resolved : $path;
    }
}
