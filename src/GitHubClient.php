<?php

declare(strict_types=1);

namespace MageSec;

use RuntimeException;

final class GitHubClient
{
    public function __construct(private readonly string $token)
    {
    }

    public function listDirectory(string $repository, string $path, string $ref): array
    {
        $url = sprintf(
            'https://api.github.com/repos/%s/contents/%s?ref=%s',
            $repository,
            str_replace('%2F', '/', rawurlencode($path)),
            rawurlencode($ref)
        );

        return $this->requestJson('GET', $url);
    }

    public function requestJson(string $method, string $url, ?array $body = null): array
    {
        $response = $this->request($method, $url, $body === null ? null : Json::encode($body), ['Content-Type: application/json']);
        $decoded = Json::decodeString($response['body'], $url);

        if (array_is_list($decoded)) {
            return $decoded;
        }

        return $decoded;
    }

    public function requestString(string $method, string $url): string
    {
        $response = $this->request($method, $url, null, []);
        return $response['body'];
    }

    public function requestRaw(string $method, string $url, ?string $body = null, array $headers = []): array
    {
        return $this->request($method, $url, $body, $headers);
    }

    private function request(string $method, string $url, ?string $body, array $headers): array
    {
        $requestHeaders = array_merge([
            'Accept: application/vnd.github+json',
            'User-Agent: magesec-action',
            'X-GitHub-Api-Version: 2022-11-28',
        ], $headers);

        if ($this->token !== '') {
            $requestHeaders[] = 'Authorization: Bearer ' . $this->token;
        }

        $context = stream_context_create([
            'http' => [
                'method' => $method,
                'ignore_errors' => true,
                'header' => implode("\r\n", $requestHeaders),
                'content' => $body ?? '',
                'timeout' => 30,
            ],
        ]);

        $responseBody = @file_get_contents($url, false, $context);
        $responseHeaders = $http_response_header ?? [];
        $statusCode = $this->extractStatusCode($responseHeaders);

        if ($responseBody === false) {
            throw new RuntimeException(sprintf('GitHub request failed for %s.', $url));
        }

        if ($statusCode >= 400) {
            throw new RuntimeException(sprintf('GitHub request failed for %s with status %d: %s', $url, $statusCode, $responseBody));
        }

        return [
            'status' => $statusCode,
            'headers' => $responseHeaders,
            'body' => $responseBody,
        ];
    }

    private function extractStatusCode(array $headers): int
    {
        foreach ($headers as $header) {
            if (preg_match('#HTTP/[0-9.]+\s+(\d{3})#', $header, $matches) === 1) {
                return (int) $matches[1];
            }
        }

        return 200;
    }
}