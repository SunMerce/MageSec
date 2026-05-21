<?php

declare(strict_types=1);

namespace MageSec;

use Closure;
use RuntimeException;
use Throwable;

final class OsvClient
{
    public function __construct(
        private readonly string $baseUrl = 'https://api.osv.dev/v1',
        private readonly ?Closure $requester = null,
    ) {
    }

    public function queryProject(array $project): array
    {
        $packages = $this->buildPackageQueries($project['installed_packages'] ?? []);
        if ($packages === []) {
            return [];
        }

        $baseUrl = rtrim($this->baseUrl, '/');
        $batchResponse = $this->requestJson('POST', $baseUrl . '/querybatch', [
            'queries' => array_map(static fn (array $package): array => $package['query'], $packages),
        ]);

        $results = $batchResponse['results'] ?? [];
        if (!is_array($results)) {
            throw new RuntimeException('OSV batch response did not contain a results array.');
        }

        $detailsCache = [];
        $findings = [];

        foreach ($results as $index => $result) {
            if (!isset($packages[$index]) || !is_array($result)) {
                continue;
            }

            foreach (($result['vulns'] ?? []) as $vulnerabilityReference) {
                if (!is_array($vulnerabilityReference)) {
                    continue;
                }

                $vulnerabilityId = (string) ($vulnerabilityReference['id'] ?? '');
                if ($vulnerabilityId === '') {
                    continue;
                }

                if (!array_key_exists($vulnerabilityId, $detailsCache)) {
                    $detailsCache[$vulnerabilityId] = $this->requestJson('GET', $baseUrl . '/vulns/' . rawurlencode($vulnerabilityId));
                }

                $findings[] = $this->normalizeFinding($packages[$index]['package'], $detailsCache[$vulnerabilityId]);
            }
        }

        return $findings;
    }

    private function buildPackageQueries(mixed $installedPackages): array
    {
        if (!is_array($installedPackages)) {
            return [];
        }

        $queries = [];
        foreach ($installedPackages as $name => $version) {
            if (!is_string($name) || $name === '' || !is_string($version) || $version === '') {
                continue;
            }

            $queries[] = [
                'package' => [
                    'name' => $name,
                    'version' => $version,
                ],
                'query' => [
                    'package' => [
                        'purl' => sprintf('pkg:composer/%s@%s', $name, $version),
                    ],
                ],
            ];
        }

        return $queries;
    }

    private function normalizeFinding(array $package, array $vulnerability): array
    {
        $aliases = array_values(array_unique(array_filter(array_map(
            'strval',
            array_merge([$vulnerability['id'] ?? ''], $vulnerability['aliases'] ?? [])
        ))));
        $cve = $this->primaryAlias($aliases, 'CVE-') ?? (string) ($vulnerability['id'] ?? 'OSV');

        [$severity, $cvss] = $this->severity($vulnerability);
        $summary = trim((string) ($vulnerability['summary'] ?? ''));
        $details = trim((string) ($vulnerability['details'] ?? ''));

        return [
            'id' => (string) ($vulnerability['id'] ?? $cve),
            'aliases' => $aliases,
            'cve' => $cve,
            'title' => $summary !== '' ? $summary : $cve,
            'severity' => $severity,
            'cvss' => $cvss,
            'description' => $details !== '' ? $details : ($summary !== '' ? $summary : $cve),
            'impact' => [],
            'references' => $this->references($vulnerability['references'] ?? []),
            'matched_constraint' => null,
            'selected_remediation' => null,
            'source' => 'osv',
            'report_mode' => 'standalone',
            'source_file' => '',
            'package_name' => (string) ($package['name'] ?? ''),
            'package_version' => (string) ($package['version'] ?? ''),
        ];
    }

    private function references(mixed $references): array
    {
        if (!is_array($references)) {
            return [];
        }

        $normalized = [];
        foreach ($references as $reference) {
            if (!is_array($reference)) {
                continue;
            }

            $url = (string) ($reference['url'] ?? '');
            if ($url === '') {
                continue;
            }

            $title = (string) ($reference['type'] ?? 'Reference');
            $normalized[] = [
                'title' => $title,
                'url' => $url,
            ];
        }

        return $normalized;
    }

    private function severity(array $vulnerability): array
    {
        $databaseSpecificSeverity = strtolower((string) ($vulnerability['database_specific']['severity'] ?? ''));
        if (in_array($databaseSpecificSeverity, ['critical', 'high', 'medium', 'low'], true)) {
            return [$databaseSpecificSeverity, null];
        }

        foreach (($vulnerability['severity'] ?? []) as $severity) {
            if (!is_array($severity)) {
                continue;
            }

            $score = $severity['score'] ?? null;
            if (is_numeric($score)) {
                $cvss = (float) $score;
                return [$this->severityFromScore($cvss), $cvss];
            }
        }

        return ['medium', null];
    }

    private function severityFromScore(float $score): string
    {
        return match (true) {
            $score >= 9.0 => 'critical',
            $score >= 7.0 => 'high',
            $score >= 4.0 => 'medium',
            default => 'low',
        };
    }

    private function primaryAlias(array $aliases, string $prefix): ?string
    {
        foreach ($aliases as $alias) {
            if (str_starts_with($alias, $prefix)) {
                return $alias;
            }
        }

        return null;
    }

    private function requestJson(string $method, string $url, ?array $payload = null): array
    {
        if ($this->requester !== null) {
            $response = ($this->requester)($method, $url, $payload);
            if (!is_array($response)) {
                throw new RuntimeException('Mock OSV requester must return an array response.');
            }

            return $response;
        }

        $headers = [
            'Accept: application/json',
            'Content-Type: application/json',
            'User-Agent: magesec-action',
        ];

        $context = stream_context_create([
            'http' => [
                'method' => $method,
                'ignore_errors' => true,
                'header' => implode("\r\n", $headers),
                'content' => $payload === null ? '' : Json::encode($payload),
                'timeout' => 30,
            ],
        ]);

        $responseBody = @file_get_contents($url, false, $context);
        $responseHeaders = $http_response_header ?? [];
        $statusCode = $this->statusCode($responseHeaders);

        if ($responseBody === false) {
            throw new RuntimeException(sprintf('OSV request failed for %s.', $url));
        }

        if ($statusCode >= 400) {
            throw new RuntimeException(sprintf('OSV request failed for %s with status %d: %s', $url, $statusCode, $responseBody));
        }

        try {
            $decoded = json_decode($responseBody, true, 512, JSON_THROW_ON_ERROR);
        } catch (Throwable $exception) {
            throw new RuntimeException(sprintf('Invalid JSON returned by OSV for %s: %s', $url, $exception->getMessage()));
        }

        if (!is_array($decoded)) {
            throw new RuntimeException(sprintf('Unexpected OSV response type for %s.', $url));
        }

        return $decoded;
    }

    private function statusCode(array $headers): int
    {
        foreach ($headers as $header) {
            if (preg_match('#HTTP/[0-9.]+\s+(\d{3})#', $header, $matches) === 1) {
                return (int) $matches[1];
            }
        }

        return 200;
    }
}