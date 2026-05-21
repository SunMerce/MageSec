<?php

declare(strict_types=1);

namespace MageSec;

final class SarifGenerator
{
    public function generate(array $project, array $matches, string $toolName): array
    {
        $rules = [];
        $results = [];

        foreach ($matches as $match) {
            $ruleId = $match['cve'];
            $rules[$ruleId] = [
                'id' => $ruleId,
                'name' => $match['title'],
                'shortDescription' => ['text' => $match['title']],
                'fullDescription' => ['text' => $match['description']],
                'help' => [
                    'text' => $this->helpText($match),
                    'markdown' => $this->helpMarkdown($match),
                ],
                'helpUri' => $match['references'][0]['url'] ?? null,
                'properties' => [
                    'security-severity' => $this->securitySeverity($match['severity'], $match['cvss']),
                    'tags' => ['security', 'magento', 'dependency'],
                ],
            ];

            $results[] = [
                'ruleId' => $ruleId,
                'level' => $this->sarifLevel($match['severity']),
                'message' => [
                    'text' => $this->resultMessage($project, $match),
                ],
                'locations' => [[
                    'physicalLocation' => [
                        'artifactLocation' => ['uri' => basename((string) $project['composer_lock_path'])],
                        'region' => ['startLine' => 1],
                    ],
                ]],
                'partialFingerprints' => [
                    'primaryLocationLineHash' => sha1($ruleId . ':' . (string) $project['edition_package'] . ':' . (string) $project['version']),
                ],
            ];
        }

        return [
            '$schema' => 'https://json.schemastore.org/sarif-2.1.0.json',
            'version' => '2.1.0',
            'runs' => [[
                'tool' => [
                    'driver' => [
                        'name' => $toolName,
                        'informationUri' => 'https://github.com/magesec/magesec',
                        'rules' => array_values($rules),
                    ],
                ],
                'results' => $results,
            ]],
        ];
    }

    private function resultMessage(array $project, array $match): string
    {
        $packageName = (string) ($match['package_name'] ?? $project['edition_package']);
        $packageVersion = (string) ($match['package_version'] ?? $project['version']);
        $base = sprintf(
            '%s %s is affected by %s (%s).',
            $packageName,
            $packageVersion,
            $match['title'],
            $match['cve']
        );

        if ($match['selected_remediation'] === null) {
            return $base . ' No automated remediation is currently configured.';
        }

        $description = trim((string) ($match['selected_remediation']['description'] ?? 'Review the configured remediation.'));
        return $base . ' ' . $description;
    }

    private function helpText(array $match): string
    {
        $lines = [$match['description']];
        foreach ($match['impact'] as $item) {
            $lines[] = '- ' . $item;
        }
        foreach ($match['references'] as $reference) {
            if (!is_array($reference) || !isset($reference['title'], $reference['url'])) {
                continue;
            }
            $lines[] = sprintf('%s: %s', $reference['title'], $reference['url']);
        }

        return implode("\n", $lines);
    }

    private function helpMarkdown(array $match): string
    {
        $lines = [trim($match['description'])];
        if ($match['impact'] !== []) {
            $lines[] = '';
            $lines[] = 'Impact:';
            foreach ($match['impact'] as $item) {
                $lines[] = '- ' . $item;
            }
        }
        if ($match['references'] !== []) {
            $lines[] = '';
            $lines[] = 'References:';
            foreach ($match['references'] as $reference) {
                if (!is_array($reference) || !isset($reference['title'], $reference['url'])) {
                    continue;
                }
                $lines[] = sprintf('- [%s](%s)', $reference['title'], $reference['url']);
            }
        }

        return implode("\n", $lines);
    }

    private function sarifLevel(string $severity): string
    {
        return match ($severity) {
            'critical', 'high' => 'error',
            'medium' => 'warning',
            default => 'note',
        };
    }

    private function securitySeverity(string $severity, mixed $cvss): string
    {
        if (is_numeric($cvss)) {
            return number_format((float) $cvss, 1, '.', '');
        }

        return match ($severity) {
            'critical' => '9.0',
            'high' => '7.0',
            'medium' => '4.0',
            default => '1.0',
        };
    }
}