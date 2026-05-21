<?php

declare(strict_types=1);

namespace MageSec;

use RuntimeException;
use Throwable;

final class Json
{
    public static function decodeFile(string $path): array
    {
        if (!is_file($path)) {
            throw new RuntimeException(sprintf('JSON file not found: %s', $path));
        }

        $contents = file_get_contents($path);
        if ($contents === false) {
            throw new RuntimeException(sprintf('Unable to read JSON file: %s', $path));
        }

        return self::decodeString($contents, $path);
    }

    public static function decodeString(string $json, string $context): array
    {
        try {
            $decoded = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        } catch (Throwable $exception) {
            throw new RuntimeException(sprintf('Invalid JSON in %s: %s', $context, $exception->getMessage()));
        }

        if (!is_array($decoded)) {
            throw new RuntimeException(sprintf('Expected JSON object or array in %s.', $context));
        }

        return $decoded;
    }

    public static function encode(mixed $value): string
    {
        try {
            return json_encode($value, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . PHP_EOL;
        } catch (Throwable $exception) {
            throw new RuntimeException(sprintf('Unable to encode JSON: %s', $exception->getMessage()));
        }
    }

    public static function encodeComposerManifest(array $manifest): string
    {
        return self::encode(self::normalizeComposerManifest($manifest));
    }

    private static function normalizeComposerManifest(mixed $value, array $path = []): mixed
    {
        if (!is_array($value)) {
            return $value;
        }

        foreach ($value as $key => $child) {
            $value[$key] = self::normalizeComposerManifest($child, [...$path, (string) $key]);
        }

        $currentPath = implode('.', $path);
        if ($value === [] && in_array($currentPath, [
            'autoload',
            'autoload-dev',
            'config',
            'extra',
            'extra.composer-patches',
            'extra.patches',
            'require',
            'require-dev',
            'scripts',
        ], true)) {
            return (object) [];
        }

        return $value;
    }
}