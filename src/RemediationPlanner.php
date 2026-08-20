<?php

declare(strict_types=1);

namespace MageSec;

final class RemediationPlanner
{
    /**
     * Build a deterministic remediation plan from matched vulnerabilities.
     *
     * Only registry matches with a selected composer-update remediation that
     * carries explicit target packages are planned. The plan is keyed by
     * package name so overlapping matches converge on the highest target.
     */
    public function plan(array $project, array $matches): array
    {
        $targets = [];
        $advisories = [];

        foreach ($matches as $match) {
            if (!is_array($match)) {
                continue;
            }

            $remediation = $match['selected_remediation'] ?? null;
            if (!is_array($remediation) || ($remediation['type'] ?? '') !== 'composer-update') {
                continue;
            }

            $packages = $this->targetPackages($project, $remediation);
            if ($packages === []) {
                continue;
            }

            $advisories[] = [
                'id' => (string) ($match['id'] ?? ''),
                'cve' => (string) ($match['cve'] ?? ''),
                'title' => (string) ($match['title'] ?? ''),
                'severity' => (string) ($match['severity'] ?? ''),
                'phase' => (string) ($remediation['phase'] ?? 'official'),
                'description' => (string) ($remediation['description'] ?? ''),
                'packages' => $packages,
            ];

            foreach ($packages as $package => $targetVersion) {
                $current = $project['installed_packages'][$package]
                    ?? $project['requirements'][$package]
                    ?? null;

                if (!is_string($current) || $current === '') {
                    continue;
                }

                if (isset($targets[$package]) && Version::compare($targets[$package]['target'], $targetVersion) >= 0) {
                    continue;
                }

                $targets[$package] = [
                    'package' => $package,
                    'current' => $current,
                    'target' => $targetVersion,
                ];
            }
        }

        if ($targets === []) {
            return [
                'updates' => [],
                'advisories' => [],
            ];
        }

        ksort($targets);

        return [
            'updates' => array_values($targets),
            'advisories' => $advisories,
        ];
    }

    /**
     * Apply the planned updates to composer.json requirements.
     *
     * Returns the list of applied updates; the manifest is modified in place.
     */
    public function applyToManifest(array &$composerJson, array $plan): array
    {
        $applied = [];

        foreach ($plan['updates'] as $update) {
            $package = $update['package'];
            $section = isset($composerJson['require'][$package]) ? 'require' : null;
            if ($section === null && isset($composerJson['require-dev'][$package])) {
                $section = 'require-dev';
            }
            if ($section === null) {
                continue;
            }

            $composerJson[$section][$package] = $update['target'];
            $applied[] = $update;
        }

        return $applied;
    }

    private function targetPackages(array $project, array $remediation): array
    {
        $packages = [];

        // Flat form: packages: { name: version }
        foreach (($remediation['packages'] ?? []) as $name => $version) {
            if (is_string($name) && is_string($version) && $version !== '') {
                $packages[$name] = $version;
            }
        }

        // Targeted form: targets: [ { when: {name: constraint}, packages: {name: version} } ]
        foreach (($remediation['targets'] ?? []) as $target) {
            if (!is_array($target)) {
                continue;
            }

            $when = $target['when'] ?? [];
            if (!$this->whenMatches($project, is_array($when) ? $when : [])) {
                continue;
            }

            foreach (($target['packages'] ?? []) as $name => $version) {
                if (is_string($name) && is_string($version) && $version !== '') {
                    $packages[$name] = $version;
                }
            }
        }

        return $packages;
    }

    private function whenMatches(array $project, array $when): bool
    {
        foreach ($when as $package => $constraint) {
            if (!is_string($package) || !is_string($constraint)) {
                continue;
            }

            $version = $project['installed_packages'][$package]
                ?? $project['requirements'][$package]
                ?? null;

            if (!is_string($version) || $version === '') {
                return false;
            }

            if (!Version::satisfies($version, $constraint)) {
                return false;
            }
        }

        return true;
    }
}
