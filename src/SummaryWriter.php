<?php

declare(strict_types=1);

namespace MageSec;

final class SummaryWriter
{
    public function write(array $project, array $matches, string $sarifPath, ?array $prResult = null): void
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

        if ($prResult !== null) {
            $lines[] = '';
            $lines[] = '## Remediation Pull Request';
            if (isset($prResult['url'])) {
                $lines[] = sprintf('- PR: %s', $prResult['url']);
                $lines[] = sprintf('- Branch: `%s`', $prResult['branch']);
            } elseif (isset($prResult['skipped_reason'])) {
                $lines[] = sprintf('- Skipped: %s', $prResult['skipped_reason']);
            }
        }

        file_put_contents($summaryPath, implode("\n", $lines) . "\n", FILE_APPEND);
    }
}