<?php

declare(strict_types=1);

namespace MageSec;

final class StateManager
{
    public function load(string $workspace): array
    {
        $path = $this->path($workspace);
        if (!is_file($path)) {
            return ['vulnerabilities' => []];
        }

        return Json::decodeFile($path);
    }

    public function record(string $workspace, string $vulnerabilityId, array $remediation): void
    {
        $state = $this->load($workspace);
        $state['vulnerabilities'][$vulnerabilityId] = [
            'phase' => $remediation['phase'] ?? null,
            'type' => $remediation['type'] ?? null,
            'updated_at' => gmdate(DATE_ATOM),
        ];

        file_put_contents($this->path($workspace), Json::encode($state));
    }

    private function path(string $workspace): string
    {
        return rtrim($workspace, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . '.magesec-state.json';
    }
}