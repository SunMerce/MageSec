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

    public function match(array $project, array $registry, array $state, string $threshold): array
    {
        $matches = [];
        $editionPackage = $project['edition_package'];
        $version = $project['version'];

        if (!is_string($editionPackage) || $editionPackage === '' || !is_string($version) || $version === '') {
            return [];
        }

        $minimumSeverity = self::SEVERITY_ORDER[$threshold] ?? self::SEVERITY_ORDER['low'];

        foreach ($registry as $entry) {
            $severity = strtolower((string) ($entry['severity'] ?? 'low'));
            if ((self::SEVERITY_ORDER[$severity] ?? 0) < $minimumSeverity) {
                continue;
            }

            $constraint = $entry['affected_versions'][$editionPackage] ?? null;
            if (!is_string($constraint) || !Version::satisfies($version, $constraint)) {
                continue;
            }

            $selectedRemediation = $this->selectRemediation($entry, $state['vulnerabilities'][$entry['id']] ?? null);
            $matches[] = [
                'id' => (string) $entry['id'],
                'cve' => (string) ($entry['cve'] ?? $entry['id']),
                'title' => (string) $entry['title'],
                'severity' => $severity,
                'cvss' => $entry['cvss'] ?? null,
                'description' => (string) $entry['description'],
                'impact' => is_array($entry['impact'] ?? null) ? $entry['impact'] : [],
                'references' => is_array($entry['references'] ?? null) ? $entry['references'] : [],
                'matched_constraint' => $constraint,
                'selected_remediation' => $selectedRemediation,
                'source_file' => (string) ($entry['source_file'] ?? ''),
            ];
        }

        usort($matches, static function (array $left, array $right): int {
            $leftSeverity = self::SEVERITY_ORDER[$left['severity']] ?? 0;
            $rightSeverity = self::SEVERITY_ORDER[$right['severity']] ?? 0;
            return $rightSeverity <=> $leftSeverity;
        });

        return $matches;
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
}