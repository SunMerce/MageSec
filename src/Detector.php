<?php

declare(strict_types=1);

namespace MageSec;

use RuntimeException;

final class Detector
{
    private const EDITION_PACKAGES = [
        'magento/magento-cloud-metapackage' => 'cloud',
        'magento/product-enterprise-edition' => 'commerce',
        'magento/product-community-edition' => 'opensource',
    ];

    public function detect(string $workspace, string $composerPath): array
    {
        $root = rtrim($workspace, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . trim($composerPath, DIRECTORY_SEPARATOR);
        $root = rtrim($root, DIRECTORY_SEPARATOR);

        $composerJsonPath = $root . DIRECTORY_SEPARATOR . 'composer.json';
        $composerLockPath = $root . DIRECTORY_SEPARATOR . 'composer.lock';

        if (!is_file($composerJsonPath) || !is_file($composerLockPath)) {
            throw new RuntimeException(sprintf('Expected Magento composer.json and composer.lock under %s.', $root));
        }

        $composerJson = Json::decodeFile($composerJsonPath);
        $composerLock = Json::decodeFile($composerLockPath);

        $installedPackages = [];
        foreach (['packages', 'packages-dev'] as $section) {
            foreach ($composerLock[$section] ?? [] as $package) {
                if (!is_array($package) || !isset($package['name'], $package['version'])) {
                    continue;
                }
                $installedPackages[(string) $package['name']] = (string) $package['version'];
            }
        }

        $editionPackage = null;
        $version = null;
        foreach (self::EDITION_PACKAGES as $packageName => $edition) {
            if (isset($installedPackages[$packageName])) {
                $editionPackage = $packageName;
                $version = $installedPackages[$packageName];
                break;
            }
        }

        if ($editionPackage === null) {
            foreach (self::EDITION_PACKAGES as $packageName => $edition) {
                $constraint = $composerJson['require'][$packageName] ?? null;
                if (is_string($constraint)) {
                    $editionPackage = $packageName;
                    $version = $constraint;
                    break;
                }
            }
        }

        $patches = $this->detectComposerPatches($root, $composerJson);

        return [
            'root' => $root,
            'composer_json_path' => $composerJsonPath,
            'composer_lock_path' => $composerLockPath,
            'composer_json' => $composerJson,
            'composer_lock' => $composerLock,
            'requirements' => $composerJson['require'] ?? [],
            'installed_packages' => $installedPackages,
            'edition' => $editionPackage === null ? 'unknown' : self::EDITION_PACKAGES[$editionPackage],
            'edition_package' => $editionPackage,
            'version' => $version,
            'patches' => $patches,
        ];
    }

    private function detectComposerPatches(string $root, array $composerJson): array
    {
        $patches = [];

        foreach (($composerJson['extra']['patches'] ?? []) as $package => $entries) {
            if (!is_array($entries)) {
                continue;
            }

            foreach ($entries as $description => $source) {
                if (!is_string($description) || !is_string($source)) {
                    continue;
                }

                $patches[] = [
                    'package' => $package,
                    'description' => $description,
                    'source' => $source,
                ];
            }
        }

        $patchesFile = $composerJson['extra']['composer-patches']['patches-file'] ?? null;
        if (!is_string($patchesFile) || $patchesFile === '') {
            return $patches;
        }

        $patchesPath = $root . DIRECTORY_SEPARATOR . $patchesFile;
        if (!is_file($patchesPath)) {
            return $patches;
        }

        $patchFileJson = Json::decodeFile($patchesPath);
        foreach (($patchFileJson['patches'] ?? []) as $package => $entries) {
            if (!is_array($entries)) {
                continue;
            }

            foreach ($entries as $description => $source) {
                if (!is_string($description) || !is_string($source)) {
                    continue;
                }

                $patches[] = [
                    'package' => $package,
                    'description' => $description,
                    'source' => $source,
                ];
            }
        }

        return $patches;
    }
}