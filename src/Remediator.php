<?php

declare(strict_types=1);

namespace MageSec;

use RuntimeException;

final class Remediator
{
    public function __construct(
        private readonly string $actionPath,
        private readonly StateManager $stateManager,
    ) {
    }

    public function apply(string $workspace, array $project, array $matches, array $state): array
    {
        $composerJson = $project['composer_json'];
        $changedFiles = [];
        $planned = [];
        $warnings = [];

        foreach ($matches as $match) {
            $remediation = $match['selected_remediation'];
            if (!is_array($remediation)) {
                continue;
            }

            $planned[] = [
                'id' => $match['id'],
                'cve' => $match['cve'],
                'type' => $remediation['type'],
                'phase' => $remediation['phase'] ?? null,
            ];

            switch ($remediation['type']) {
                case 'composer-update':
                case 'composer-require':
                    $composerJson = $this->applyComposerPackages($composerJson, $project, $remediation);
                    break;

                case 'patch':
                    [$composerJson, $patchChangedFiles] = $this->applyPatch($workspace, $composerJson, $remediation);
                    $changedFiles = array_merge($changedFiles, $patchChangedFiles);
                    break;

                default:
                    $warnings[] = sprintf('Unsupported remediation type %s for %s.', $remediation['type'], $match['id']);
                    continue 2;
            }

            $this->cleanupSupersededArtifacts($workspace, $composerJson, $remediation);
            $this->stateManager->record($workspace, $match['id'], $remediation);
        }

        $composerJsonPath = $project['composer_json_path'];
        $original = Json::encodeComposerManifest($project['composer_json']);
        $updated = Json::encodeComposerManifest($composerJson);
        if ($original !== $updated) {
            file_put_contents($composerJsonPath, $updated);
            $changedFiles[] = $this->relativePath($workspace, $composerJsonPath);
        }

        $statePath = $workspace . DIRECTORY_SEPARATOR . '.magesec-state.json';
        if (is_file($statePath)) {
            $changedFiles[] = '.magesec-state.json';
        }

        return [
            'planned' => $planned,
            'changed_files' => array_values(array_unique($changedFiles)),
            'warnings' => $warnings,
        ];
    }

    private function applyComposerPackages(array $composerJson, array $project, array $remediation): array
    {
        $packages = $this->resolvePackagesForProject($project, $remediation);
        if ($packages === []) {
            throw new RuntimeException(sprintf('Remediation %s does not resolve to any packages for this project.', $remediation['phase'] ?? 'unknown'));
        }

        $composerJson['require'] ??= [];
        foreach ($packages as $package => $version) {
            $composerJson['require'][$package] = $version;
        }

        return $composerJson;
    }

    private function applyPatch(string $workspace, array $composerJson, array $remediation): array
    {
        $targetPackage = $remediation['target_package'] ?? null;
        $patchFile = $remediation['patch_file'] ?? null;
        $description = $remediation['patch_description'] ?? ($remediation['description'] ?? 'MageSec patch');

        if (!is_string($targetPackage) || !is_string($patchFile) || !is_string($description)) {
            throw new RuntimeException('Patch remediation is missing target_package, patch_file, or description.');
        }

        $sourcePath = $this->actionPath . DIRECTORY_SEPARATOR . $patchFile;
        if (!is_file($sourcePath)) {
            throw new RuntimeException(sprintf('Patch file not found: %s', $sourcePath));
        }

        $targetDirectory = $workspace . DIRECTORY_SEPARATOR . '.magesec' . DIRECTORY_SEPARATOR . 'patches';
        if (!is_dir($targetDirectory) && !mkdir($targetDirectory, 0777, true) && !is_dir($targetDirectory)) {
            throw new RuntimeException(sprintf('Unable to create patch directory: %s', $targetDirectory));
        }

        $targetPath = $targetDirectory . DIRECTORY_SEPARATOR . basename($patchFile);
        copy($sourcePath, $targetPath);

        $relativePath = '.magesec/patches/' . basename($patchFile);
        $composerJson['extra']['patches'][$targetPackage][$description] = $relativePath;

        return [$composerJson, [$relativePath]];
    }

    private function cleanupSupersededArtifacts(string $workspace, array &$composerJson, array $remediation): void
    {
        foreach ($remediation['cleanup_patch_descriptions'] ?? [] as $package => $descriptions) {
            if (!is_array($descriptions)) {
                continue;
            }
            foreach ($descriptions as $description) {
                unset($composerJson['extra']['patches'][$package][$description]);
            }
            if (($composerJson['extra']['patches'][$package] ?? []) === []) {
                unset($composerJson['extra']['patches'][$package]);
            }
        }

        foreach ($remediation['cleanup_patch_files'] ?? [] as $relativePath) {
            if (!is_string($relativePath) || $relativePath === '') {
                continue;
            }
            $absolutePath = $workspace . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relativePath);
            if (is_file($absolutePath)) {
                unlink($absolutePath);
            }
        }
    }

    private function resolvePackagesForProject(array $project, array $remediation): array
    {
        if (isset($remediation['targets']) && is_array($remediation['targets'])) {
            foreach ($remediation['targets'] as $target) {
                if (!is_array($target) || !isset($target['when'], $target['packages']) || !is_array($target['when']) || !is_array($target['packages'])) {
                    continue;
                }

                foreach ($target['when'] as $package => $constraint) {
                    if ($package !== $project['edition_package']) {
                        continue;
                    }

                    if (Version::satisfies((string) $project['version'], (string) $constraint)) {
                        return $target['packages'];
                    }
                }
            }
        }

        return is_array($remediation['packages'] ?? null) ? $remediation['packages'] : [];
    }

    private function relativePath(string $workspace, string $path): string
    {
        $workspace = rtrim($workspace, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
        if (str_starts_with($path, $workspace)) {
            return str_replace(DIRECTORY_SEPARATOR, '/', substr($path, strlen($workspace)));
        }

        return $path;
    }
}