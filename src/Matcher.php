<?php

declare(strict_types=1);

namespace MageSec;

final class Matcher
{
    private const SEVERITY_ORDER = [
        'low' => 1,
        'medium' => 2,
        'high' => 3,
        'critical' => 4,
    ];

    public function match(array $project, array $osvFindings, array $registry, array $state, string $threshold): array
    {
        $matches = [];
        $editionPackage = $project['edition_package'];
        $version = $project['version'];

        if (!is_string($editionPackage) || $editionPackage === '' || !is_string($version) || $version === '') {
            return [];
        }

        $minimumSeverity = self::SEVERITY_ORDER[$threshold] ?? self::SEVERITY_ORDER['low'];

        foreach ($osvFindings as $finding) {
            if (!is_array($finding)) {
                continue;
            }

            $severity = strtolower((string) ($finding['severity'] ?? 'medium'));
            if ((self::SEVERITY_ORDER[$severity] ?? 0) < $minimumSeverity) {
                continue;
            }

            $matches[] = [
                'id' => (string) ($finding['id'] ?? ''),
                'aliases' => $this->aliases($finding),
                'cve' => (string) ($finding['cve'] ?? $finding['id'] ?? 'OSV'),
                'title' => (string) ($finding['title'] ?? $finding['id'] ?? 'OSV finding'),
                'severity' => $severity,
                'cvss' => $finding['cvss'] ?? null,
                'description' => (string) ($finding['description'] ?? $finding['title'] ?? 'OSV finding'),
                'impact' => is_array($finding['impact'] ?? null) ? $finding['impact'] : [],
                'references' => is_array($finding['references'] ?? null) ? $finding['references'] : [],
                'matched_constraint' => null,
                'selected_remediation' => null,
                'source_file' => '',
                'source' => 'osv',
                'report_mode' => 'standalone',
                'package_name' => (string) ($finding['package_name'] ?? ''),
                'package_version' => (string) ($finding['package_version'] ?? ''),
            ];
        }

        foreach ($registry as $entry) {
            $registryMatch = $this->registryMatch($project, $entry, $state);
            if ($registryMatch === null) {
                continue;
            }

            if ((self::SEVERITY_ORDER[$registryMatch['severity']] ?? 0) < $minimumSeverity) {
                continue;
            }

            $overlayIndex = $this->overlayIndex($matches, $registryMatch);
            if ($overlayIndex !== null) {
                $matches[$overlayIndex] = $this->mergeOverlay($matches[$overlayIndex], $registryMatch);
                continue;
            }

            $matches[] = $registryMatch;
        }

        usort($matches, static function (array $left, array $right): int {
            $leftSeverity = self::SEVERITY_ORDER[$left['severity']] ?? 0;
            $rightSeverity = self::SEVERITY_ORDER[$right['severity']] ?? 0;
            return $rightSeverity <=> $leftSeverity;
        });

        return $matches;
    }

    private function registryMatch(array $project, array $entry, array $state): ?array
    {
        $editionPackage = $project['edition_package'];
        $version = $project['version'];
        if (!is_string($editionPackage) || $editionPackage === '' || !is_string($version) || $version === '') {
            return null;
        }

        $constraint = $entry['affected_versions'][$editionPackage] ?? null;
        if (!is_string($constraint) || !Version::satisfies($version, $constraint)) {
            return null;
        }

        $selectedRemediation = $this->selectRemediation($entry, $state['vulnerabilities'][$entry['id']] ?? null);

        return [
            'id' => (string) $entry['id'],
            'aliases' => $this->aliases($entry),
            'cve' => (string) ($entry['cve'] ?? $entry['id']),
            'title' => (string) $entry['title'],
            'severity' => strtolower((string) ($entry['severity'] ?? 'low')),
            'cvss' => $entry['cvss'] ?? null,
            'description' => (string) $entry['description'],
            'impact' => is_array($entry['impact'] ?? null) ? $entry['impact'] : [],
            'references' => is_array($entry['references'] ?? null) ? $entry['references'] : [],
            'matched_constraint' => $constraint,
            'selected_remediation' => $selectedRemediation,
            'source_file' => (string) ($entry['source_file'] ?? ''),
            'source' => 'registry',
            'detection_source' => (string) ($entry['detection_source'] ?? 'magesec-only'),
            'report_mode' => (string) ($entry['report_mode'] ?? 'standalone'),
            'package_name' => $editionPackage,
            'package_version' => $version,
        ];
    }

    private function selectRemediation(array $entry, ?array $currentState): ?array
    {
        $activeRemediations = array_values(array_filter(
            $entry['remediations'],
            static fn (array $remediation): bool => ($remediation['status'] ?? 'active') === 'active'
        ));

        if ($activeRemediations === []) {
            return null;
        }

        $currentPhase = $currentState['phase'] ?? null;
        if (is_string($currentPhase) && $currentPhase !== '') {
            foreach ($activeRemediations as $remediation) {
                $revertPhases = $remediation['revert_phases'] ?? [];
                if (is_array($revertPhases) && in_array($currentPhase, $revertPhases, true)) {
                    return $remediation;
                }
            }
        }

        foreach ($activeRemediations as $remediation) {
            if ($this->conditionMatches($remediation['condition'] ?? 'always', $currentPhase)) {
                return $remediation;
            }
        }

        return $activeRemediations[0];
    }

    private function conditionMatches(mixed $condition, ?string $currentPhase): bool
    {
        if (!is_string($condition) || $condition === '' || $condition === 'always') {
            return true;
        }

        return match ($condition) {
            'no_official_patch_applied' => $currentPhase !== 'official',
            'interim_patch_applied' => $currentPhase === 'interim',
            default => false,
        };
    }

    private function aliases(array $entry): array
    {
        $aliases = [];
        foreach ([$entry['id'] ?? null, $entry['cve'] ?? null] as $alias) {
            if (is_string($alias) && $alias !== '') {
                $aliases[] = $alias;
            }
        }

        foreach (($entry['aliases'] ?? []) as $alias) {
            if (is_string($alias) && $alias !== '') {
                $aliases[] = $alias;
            }
        }

        return array_values(array_unique($aliases));
    }

    private function overlayIndex(array $matches, array $overlay): ?int
    {
        if (($overlay['detection_source'] ?? 'magesec-only') !== 'osv-overlay') {
            return null;
        }

        $overlayAliases = array_map('strtoupper', $overlay['aliases']);
        foreach ($matches as $index => $match) {
            if (!is_array($match) || !str_starts_with((string) ($match['source'] ?? ''), 'osv')) {
                continue;
            }

            if (($overlay['package_name'] ?? '') !== '' && ($match['package_name'] ?? '') !== ($overlay['package_name'] ?? '')) {
                continue;
            }

            $matchAliases = array_map('strtoupper', $match['aliases'] ?? []);
            if (array_intersect($overlayAliases, $matchAliases) !== []) {
                return $index;
            }
        }

        return null;
    }

    private function mergeOverlay(array $base, array $overlay): array
    {
        $base['id'] = $overlay['id'];
        $base['aliases'] = array_values(array_unique(array_merge($base['aliases'] ?? [], $overlay['aliases'] ?? [])));
        $base['cve'] = $overlay['cve'] !== '' ? $overlay['cve'] : $base['cve'];
        $base['title'] = $overlay['title'] !== '' ? $overlay['title'] : $base['title'];
        $base['severity'] = $this->higherSeverity($base['severity'], $overlay['severity']);
        $base['cvss'] = $overlay['cvss'] ?? $base['cvss'];
        $base['description'] = $overlay['description'] !== '' ? $overlay['description'] : $base['description'];
        $base['impact'] = $overlay['impact'] !== [] ? $overlay['impact'] : $base['impact'];
        $base['references'] = $this->mergeReferences($base['references'] ?? [], $overlay['references'] ?? []);
        $base['matched_constraint'] = $overlay['matched_constraint'];
        $base['selected_remediation'] = $overlay['selected_remediation'];
        $base['source_file'] = $overlay['source_file'];
        $base['source'] = 'osv+registry';
        $base['report_mode'] = $overlay['report_mode'];

        return $base;
    }

    private function higherSeverity(string $left, string $right): string
    {
        return (self::SEVERITY_ORDER[$right] ?? 0) > (self::SEVERITY_ORDER[$left] ?? 0) ? $right : $left;
    }

    private function mergeReferences(array $base, array $overlay): array
    {
        $merged = [];
        $seen = [];

        foreach (array_merge($base, $overlay) as $reference) {
            if (!is_array($reference)) {
                continue;
            }

            $url = (string) ($reference['url'] ?? '');
            if ($url === '' || isset($seen[$url])) {
                continue;
            }

            $seen[$url] = true;
            $merged[] = $reference;
        }

        return $merged;
    }
}