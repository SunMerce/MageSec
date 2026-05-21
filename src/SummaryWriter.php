<?php

declare(strict_types=1);

namespace MageSec;

final class SummaryWriter
{
    public function write(array $project, array $matches, string $sarifPath, array $remediationResult, array $prResult, array $issueResult): void
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

        if ($remediationResult['changed_files'] !== []) {
            $lines[] = '';
            $lines[] = '## Changed Files';
            foreach ($remediationResult['changed_files'] as $file) {
                $lines[] = '- ' . $file;
            }
        }

        if (($prResult['url'] ?? null) !== null) {
            $lines[] = '';
            $lines[] = '## Pull Request';
            $lines[] = sprintf('- %s', $prResult['url']);
        } elseif (($prResult['skipped_reason'] ?? null) !== null) {
            $lines[] = '';
            $lines[] = '## Pull Request';
            $lines[] = sprintf('- Skipped: %s', $prResult['skipped_reason']);
        }

        if (($issueResult['url'] ?? null) !== null) {
            $lines[] = '';
            $lines[] = '## Status Issue';
            $lines[] = sprintf('- %s', $issueResult['url']);
        } elseif (($issueResult['skipped_reason'] ?? null) !== null) {
            $lines[] = '';
            $lines[] = '## Status Issue';
            $lines[] = sprintf('- Skipped: %s', $issueResult['skipped_reason']);
        }

        file_put_contents($summaryPath, implode("\n", $lines) . "\n", FILE_APPEND);
    }
}