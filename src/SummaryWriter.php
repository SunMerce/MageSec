<?php

declare(strict_types=1);

namespace MageSec;

final class SummaryWriter
{
    public function write(array $project, array $matches, string $sarifPath): void
    {
        $summaryPath = getenv('GITHUB_STEP_SUMMARY');
        if ($summaryPath === false || $summaryPath === '') {
            return;
        }

        $lines = [
            '# MageSec Scan Summary',
            '',
            sprintf('- Edition: %s', $project['edition']),
            sprintf('- Package: %s', $project['edition_package'] ?? 'unknown'),
            sprintf('- Version: %s', $project['version'] ?? 'unknown'),
            sprintf('- Vulnerabilities found: %d', count($matches)),
            sprintf('- SARIF file: %s', $sarifPath),
        ];

        if ($matches !== []) {
            $lines[] = '';
            $lines[] = '## Matched Vulnerabilities';
            foreach ($matches as $match) {
                $remediation = $match['selected_remediation'];
                $lines[] = sprintf(
                    '- %s: %s (%s)%s',
                    $match['cve'],
                    $match['title'],
                    strtoupper($match['severity']),
                    is_array($remediation) ? sprintf(' -> %s', $remediation['type']) : ''
                );
            }
        }

        file_put_contents($summaryPath, implode("\n", $lines) . "\n", FILE_APPEND);
    }
}