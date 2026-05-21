<?php

declare(strict_types=1);

namespace MageSec;

final class Version
{
    public static function compare(string $left, string $right): int
    {
        $leftParts = self::normalize($left);
        $rightParts = self::normalize($right);

        foreach ($leftParts as $index => $value) {
            $comparison = $value <=> $rightParts[$index];
            if ($comparison !== 0) {
                return $comparison;
            }
        }

        return 0;
    }

    public static function satisfies(string $version, string $constraint): bool
    {
        $constraint = trim($constraint);
        if ($constraint === '' || $constraint === '*') {
            return true;
        }

        foreach (preg_split('/\s*\|\|\s*/', $constraint) ?: [] as $group) {
            if (self::satisfiesAll($version, $group)) {
                return true;
            }
        }

        return false;
    }

    private static function satisfiesAll(string $version, string $group): bool
    {
        $group = str_replace(',', ' ', trim($group));
        if ($group === '') {
            return true;
        }

        $tokens = preg_split('/\s+/', $group) ?: [];
        foreach ($tokens as $token) {
            if ($token === '') {
                continue;
            }

            if (!self::satisfiesToken($version, $token)) {
                return false;
            }
        }

        return true;
    }

    private static function satisfiesToken(string $version, string $token): bool
    {
        if (str_contains($token, '*')) {
            $prefix = rtrim(str_replace('*', '', $token), '.');
            return $prefix === '' || str_starts_with($version, $prefix);
        }

        if (preg_match('/^(>=|<=|>|<|==|=|!=)(.+)$/', $token, $matches) === 1) {
            $operator = $matches[1];
            $target = trim($matches[2]);
        } else {
            $operator = '=';
            $target = trim($token);
        }

        $comparison = self::compare($version, $target);

        return match ($operator) {
            '>' => $comparison > 0,
            '>=' => $comparison >= 0,
            '<' => $comparison < 0,
            '<=' => $comparison <= 0,
            '!=', '<>' => $comparison !== 0,
            '=', '==' => $comparison === 0,
            default => false,
        };
    }

    private static function normalize(string $version): array
    {
        $version = trim($version);
        $suffixRank = 0;
        $patch = 0;

        if (preg_match('/^(?<base>\d+(?:\.\d+)*)(?:-p(?<patch>\d+))?(?:-(?<suffix>[A-Za-z0-9.]+))?$/', $version, $matches) !== 1) {
            return [0, 0, 0, 0, -1, 0];
        }

        $parts = array_map('intval', explode('.', $matches['base']));
        while (count($parts) < 4) {
            $parts[] = 0;
        }
        $parts = array_slice($parts, 0, 4);

        if (($matches['patch'] ?? '') !== '') {
            $patch = (int) $matches['patch'];
        }

        if (($matches['suffix'] ?? '') !== '') {
            $suffixRank = -1;
        }

        return array_merge($parts, [$suffixRank, $patch]);
    }
}