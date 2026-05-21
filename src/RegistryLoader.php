<?php

declare(strict_types=1);

namespace MageSec;

use RuntimeException;

final class RegistryLoader
{
    public function __construct(private readonly GitHubClient $client)
    {
    }

    public function load(string $actionPath, string $repository, string $ref): array
    {
        if ($repository !== '' && $ref !== '') {
            return $this->loadRemote($repository, $ref);
        }

        return $this->loadLocal($actionPath . DIRECTORY_SEPARATOR . 'registry');
    }

    private function loadLocal(string $registryPath): array
    {
        $files = glob($registryPath . DIRECTORY_SEPARATOR . '*.yml') ?: [];
        sort($files);

        $entries = [];
        foreach ($files as $file) {
            $entry = yaml_parse_file($file);
            if (!is_array($entry)) {
                throw new RuntimeException(sprintf('Invalid registry YAML: %s', $file));
            }
            $entries[] = $this->validate($entry, basename($file));
        }

        return $entries;
    }

    private function loadRemote(string $repository, string $ref): array
    {
        $entries = [];
        $listing = $this->client->listDirectory($repository, 'registry', $ref);
        foreach ($listing as $item) {
            if (!is_array($item) || ($item['type'] ?? null) !== 'file') {
                continue;
            }
            $name = (string) ($item['name'] ?? '');
            if (!str_ends_with($name, '.yml')) {
                continue;
            }

            $downloadUrl = (string) ($item['download_url'] ?? '');
            if ($downloadUrl === '') {
                continue;
            }

            $contents = $this->client->requestString('GET', $downloadUrl);
            $entry = yaml_parse($contents);
            if (!is_array($entry)) {
                throw new RuntimeException(sprintf('Invalid remote registry YAML: %s', $name));
            }
            $entries[] = $this->validate($entry, $name);
        }

        return $entries;
    }

    private function validate(array $entry, string $source): array
    {
        foreach (['id', 'title', 'severity', 'description', 'affected_versions', 'remediations'] as $requiredKey) {
            if (!array_key_exists($requiredKey, $entry)) {
                throw new RuntimeException(sprintf('Registry entry %s is missing required field %s.', $source, $requiredKey));
            }
        }

        if (!is_array($entry['affected_versions']) || !is_array($entry['remediations'])) {
            throw new RuntimeException(sprintf('Registry entry %s has invalid affected_versions or remediations.', $source));
        }

        foreach ($entry['remediations'] as $index => $remediation) {
            if (!is_array($remediation) || !isset($remediation['phase'], $remediation['type'])) {
                throw new RuntimeException(sprintf('Registry entry %s remediation #%d is invalid.', $source, $index));
            }
        }

        $entry['source_file'] = $source;
        return $entry;
    }
}