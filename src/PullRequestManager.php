<?php

declare(strict_types=1);

namespace MageSec;

use RuntimeException;

final class PullRequestManager
{
    private const API_BASE = 'https://api.github.com';

    public function __construct(
        private readonly GitHubClient $client,
        private readonly string $repository,
        private readonly string $label = 'security',
    ) {
    }

    /**
     * Create (or reuse) a remediation branch, commit the updated composer
     * files, and open a pull request labelled `security`.
     *
     * @return array{url: string, number: int, branch: string, reused: bool}
     */
    public function open(array $plan, string $composerJson, ?string $composerLock, string $composerPath, string $baseBranch): array
    {
        $branch = $this->branchName($plan);
        $baseSha = $this->refSha('heads/' . $baseBranch);

        $reused = true;
        try {
            $branchSha = $this->refSha('heads/' . $branch);
        } catch (RuntimeException) {
            $reused = false;
            $branchSha = null;
        }

        if ($branchSha === null) {
            $this->client->requestJson('POST', sprintf('%s/repos/%s/git/refs', self::API_BASE, $this->repository), [
                'ref' => 'refs/heads/' . $branch,
                'sha' => $baseSha,
            ]);
            $branchSha = $baseSha;
        }

        $this->commitFiles($branch, $branchSha, $plan, $composerJson, $composerLock, $composerPath);

        $existing = $this->findOpenPr($branch);
        if ($existing !== null) {
            return [
                'url' => (string) $existing['html_url'],
                'number' => (int) $existing['number'],
                'branch' => $branch,
                'reused' => true,
            ];
        }

        $pr = $this->client->requestJson('POST', sprintf('%s/repos/%s/pulls', self::API_BASE, $this->repository), [
            'title' => $this->title($plan),
            'head' => $branch,
            'base' => $baseBranch,
            'body' => $this->body($plan),
        ]);

        $number = (int) $pr['number'];
        $this->applyLabel($number);

        return [
            'url' => (string) $pr['html_url'],
            'number' => $number,
            'branch' => $branch,
            'reused' => $reused,
        ];
    }

    private function commitFiles(string $branch, string $branchSha, array $plan, string $composerJson, ?string $composerLock, string $composerPath): void
    {
        $prefix = trim($composerPath, '/');
        $files = [
            ($prefix === '' ? '' : $prefix . '/') . 'composer.json' => $composerJson,
        ];
        if ($composerLock !== null && $composerLock !== '') {
            $files[($prefix === '' ? '' : $prefix . '/') . 'composer.lock'] = $composerLock;
        }

        $treeEntries = [];
        foreach ($files as $path => $content) {
            $blob = $this->client->requestJson('POST', sprintf('%s/repos/%s/git/blobs', self::API_BASE, $this->repository), [
                'content' => base64_encode($content),
                'encoding' => 'base64',
            ]);
            $treeEntries[] = [
                'path' => $path,
                'mode' => '100644',
                'type' => 'blob',
                'sha' => $blob['sha'],
            ];
        }

        $tree = $this->client->requestJson('POST', sprintf('%s/repos/%s/git/trees', self::API_BASE, $this->repository), [
            'base_tree' => $branchSha,
            'tree' => $treeEntries,
        ]);

        $commit = $this->client->requestJson('POST', sprintf('%s/repos/%s/git/commits', self::API_BASE, $this->repository), [
            'message' => $this->commitMessage($plan),
            'tree' => $tree['sha'],
            'parents' => [$branchSha],
        ]);

        $this->client->requestJson('PATCH', sprintf('%s/repos/%s/git/refs/heads/%s', self::API_BASE, $this->repository, $branch), [
            'sha' => $commit['sha'],
            'force' => true,
        ]);
    }

    private function applyLabel(int $number): void
    {
        try {
            $this->client->requestJson('POST', sprintf('%s/repos/%s/issues/%d/labels', self::API_BASE, $this->repository, $number), [
                'labels' => [$this->label],
            ]);
        } catch (RuntimeException $exception) {
            // The label may not exist yet; create it and retry once.
            if (!str_contains($exception->getMessage(), '422') && !str_contains($exception->getMessage(), '404')) {
                throw $exception;
            }

            $this->client->requestJson('POST', sprintf('%s/repos/%s/labels', self::API_BASE, $this->repository), [
                'name' => $this->label,
                'color' => 'd73a4a',
                'description' => 'Security remediation',
            ]);

            $this->client->requestJson('POST', sprintf('%s/repos/%s/issues/%d/labels', self::API_BASE, $this->repository, $number), [
                'labels' => [$this->label],
            ]);
        }
    }

    private function findOpenPr(string $branch): ?array
    {
        $owner = explode('/', $this->repository)[0];
        $prs = $this->client->requestJson('GET', sprintf(
            '%s/repos/%s/pulls?state=open&head=%s:%s',
            self::API_BASE,
            $this->repository,
            rawurlencode($owner),
            rawurlencode($branch)
        ));

        return $prs[0] ?? null;
    }

    private function refSha(string $ref): string
    {
        $data = $this->client->requestJson('GET', sprintf(
            '%s/repos/%s/git/ref/%s',
            self::API_BASE,
            $this->repository,
            str_replace('%2F', '/', rawurlencode($ref))
        ));

        return (string) ($data['object']['sha'] ?? '');
    }

    private function branchName(array $plan): string
    {
        $ids = array_map(
            static fn (array $advisory): string => strtolower((string) ($advisory['cve'] ?: $advisory['id'])),
            $plan['advisories']
        );
        $ids = array_values(array_filter(array_unique($ids)));
        sort($ids);

        $suffix = substr(sha1(implode(',', $ids)), 0, 8);
        return 'magesec/security-fix-' . $suffix;
    }

    private function title(array $plan): string
    {
        $cves = array_map(
            static fn (array $advisory): string => (string) ($advisory['cve'] ?: $advisory['id']),
            $plan['advisories']
        );
        $cves = array_values(array_filter(array_unique($cves)));

        return sprintf('[MageSec] Security update: %s', implode(', ', $cves));
    }

    private function commitMessage(array $plan): string
    {
        $lines = ['chore(security): apply MageSec remediations', ''];
        foreach ($plan['updates'] as $update) {
            $lines[] = sprintf('- %s: %s -> %s', $update['package'], $update['current'], $update['target']);
        }

        return implode("\n", $lines);
    }

    private function body(array $plan): string
    {
        $lines = [
            '## MageSec security remediation',
            '',
            'This pull request was opened automatically by the MageSec scan because one or more',
            'known vulnerabilities affect the Magento packages in this repository.',
            '',
            '### Package updates',
            '',
            '| Package | From | To |',
            '| --- | --- | --- |',
        ];

        foreach ($plan['updates'] as $update) {
            $lines[] = sprintf('| `%s` | `%s` | `%s` |', $update['package'], $update['current'], $update['target']);
        }

        $lines[] = '';
        $lines[] = '### Advisories addressed';
        $lines[] = '';

        foreach ($plan['advisories'] as $advisory) {
            $lines[] = sprintf(
                '- **%s** (%s, %s): %s',
                $advisory['cve'] ?: $advisory['id'],
                strtoupper((string) $advisory['severity']),
                $advisory['phase'],
                $advisory['title']
            );
        }

        $lines[] = '';
        $lines[] = '> Review the changes and run your deployment pipeline before merging.';
        $lines[] = '> When `composer.lock` could not be regenerated in the scan environment, run `composer update` locally after merging.';

        return implode("\n", $lines);
    }
}
