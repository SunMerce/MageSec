<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

use MageSec\Detector;
use MageSec\GitHubClient;
use MageSec\IssueManager;
use MageSec\Matcher;
use MageSec\OsvClient;
use MageSec\SarifGenerator;
use MageSec\Version;

$tests = [
    'version_compare_prefers_patch_release' => static function (): void {
        assertTrue(Version::compare('2.4.6-p6', '2.4.6-p5') > 0, 'Patch releases should compare in ascending order.');
        assertTrue(Version::compare('2.4.7', '2.4.6-p6') > 0, 'Minor versions should outrank previous patch releases.');
    },
    'version_satisfies_compound_ranges' => static function (): void {
        assertTrue(Version::satisfies('2.4.6-p5', '>=2.4.6 <2.4.6-p6 || >=2.4.7 <2.4.7-p1'), 'Compound range should match vulnerable 2.4.6 branch.');
        assertTrue(!Version::satisfies('2.4.6-p6', '>=2.4.6 <2.4.6-p6 || >=2.4.7 <2.4.7-p1'), 'Patched release should not satisfy vulnerable range.');
    },
    'detector_reads_magento_fixture' => static function (): void {
        $detector = new Detector();
        $project = $detector->detect(__DIR__ . '/fixtures/opensource-vulnerable', '.');

        assertSame('opensource', $project['edition'], 'Detector should identify Magento Open Source fixture.');
        assertSame('magento/product-community-edition', $project['edition_package'], 'Detector should locate the Open Source metapackage.');
        assertSame('2.4.6-p5', $project['version'], 'Detector should read the installed version from composer.lock.');
    },
    'matcher_selects_official_remediation' => static function (): void {
        $project = [
            'edition_package' => 'magento/product-community-edition',
            'version' => '2.4.6-p5',
        ];
        $registry = [[
            'id' => 'cosmicsting',
            'cve' => 'CVE-2024-34102',
            'title' => 'CosmicSting',
            'severity' => 'critical',
            'description' => 'Fixture entry',
            'affected_versions' => [
                'magento/product-community-edition' => '>=2.4.6 <2.4.6-p6',
            ],
            'remediations' => [[
                'phase' => 'official',
                'type' => 'composer-update',
                'condition' => 'always',
                'packages' => [
                    'magento/product-community-edition' => '2.4.6-p6',
                ],
            ]],
        ]];

        $matcher = new Matcher();
        $matches = $matcher->match($project, [], $registry, ['vulnerabilities' => []], 'high');

        assertSame(1, count($matches), 'Matcher should return a single vulnerability match.');
        assertSame('composer-update', $matches[0]['selected_remediation']['type'], 'Matcher should select the official composer update remediation.');
    },
    'matcher_prefers_replacement_for_interim_phase' => static function (): void {
        $project = [
            'edition_package' => 'magento/product-community-edition',
            'version' => '2.4.6-p5',
        ];
        $registry = [[
            'id' => 'cosmicsting',
            'cve' => 'CVE-2024-34102',
            'title' => 'CosmicSting',
            'severity' => 'critical',
            'description' => 'Fixture entry',
            'affected_versions' => [
                'magento/product-community-edition' => '>=2.4.6 <2.4.6-p6',
            ],
            'remediations' => [
                [
                    'phase' => 'interim',
                    'type' => 'patch',
                    'condition' => 'no_official_patch_applied',
                ],
                [
                    'phase' => 'official',
                    'type' => 'composer-update',
                    'condition' => 'always',
                    'revert_phases' => ['interim'],
                    'packages' => [
                        'magento/product-community-edition' => '2.4.6-p6',
                    ],
                ],
            ],
        ]];

        $matcher = new Matcher();
        $matches = $matcher->match($project, [], $registry, [
            'vulnerabilities' => [
                'cosmicsting' => ['phase' => 'interim'],
            ],
        ], 'low');

        assertSame('official', $matches[0]['selected_remediation']['phase'], 'Matcher should prefer the official replacement when an interim fix is already recorded.');
    },
    'osv_client_normalizes_batch_and_detail_responses' => static function (): void {
        $client = new OsvClient('https://example.test/v1', static function (string $method, string $url, ?array $payload): array {
            if ($method === 'POST' && $url === 'https://example.test/v1/querybatch') {
                assertSame('pkg:composer/vendor/package@1.2.3', $payload['queries'][0]['package']['purl'], 'OSV client should query Composer packages using purl format.');

                return [
                    'results' => [[
                        'vulns' => [[
                            'id' => 'GHSA-test-1234',
                        ]],
                    ]],
                ];
            }

            if ($method === 'GET' && $url === 'https://example.test/v1/vulns/GHSA-test-1234') {
                return [
                    'id' => 'GHSA-test-1234',
                    'aliases' => ['CVE-2026-0001'],
                    'summary' => 'Fixture advisory',
                    'details' => 'Fixture details',
                    'database_specific' => ['severity' => 'HIGH'],
                    'references' => [[
                        'type' => 'ADVISORY',
                        'url' => 'https://example.test/advisory',
                    ]],
                ];
            }

            throw new RuntimeException(sprintf('Unexpected OSV request: %s %s', $method, $url));
        });

        $findings = $client->queryProject([
            'installed_packages' => [
                'vendor/package' => '1.2.3',
            ],
        ]);

        assertSame(1, count($findings), 'OSV client should return a normalized finding for the mocked advisory.');
        assertSame('CVE-2026-0001', $findings[0]['cve'], 'OSV client should prefer a CVE alias when present.');
        assertSame('vendor/package', $findings[0]['package_name'], 'OSV client should keep the affected package name.');
        assertSame('high', $findings[0]['severity'], 'OSV client should normalize severity labels to lowercase.');
    },
    'matcher_merges_osv_findings_with_registry_overlay' => static function (): void {
        $project = [
            'edition_package' => 'magento/product-community-edition',
            'version' => '2.4.6-p5',
        ];
        $osvFindings = [[
            'id' => 'GHSA-263x-hfm2-qh28',
            'aliases' => ['GHSA-263x-hfm2-qh28', 'CVE-2024-34102'],
            'cve' => 'CVE-2024-34102',
            'title' => 'Generic advisory title',
            'severity' => 'high',
            'description' => 'Generic advisory details',
            'references' => [],
            'package_name' => 'magento/product-community-edition',
            'package_version' => '2.4.6-p5',
        ]];
        $registry = [[
            'id' => 'cosmicsting',
            'cve' => 'CVE-2024-34102',
            'aliases' => ['GHSA-263x-hfm2-qh28'],
            'title' => 'CosmicSting',
            'severity' => 'critical',
            'description' => 'Magento-specific overlay details',
            'detection_source' => 'osv-overlay',
            'report_mode' => 'augment',
            'affected_versions' => [
                'magento/product-community-edition' => '>=2.4.6 <2.4.6-p6',
            ],
            'references' => [[
                'title' => 'Overlay reference',
                'url' => 'https://example.test/overlay',
            ]],
            'remediations' => [[
                'phase' => 'official',
                'type' => 'composer-update',
                'condition' => 'always',
                'packages' => [
                    'magento/product-community-edition' => '2.4.6-p6',
                ],
            ]],
        ]];

        $matcher = new Matcher();
        $matches = $matcher->match($project, $osvFindings, $registry, ['vulnerabilities' => []], 'medium');

        assertSame(1, count($matches), 'Matcher should merge the OSV finding and overlay into one match.');
        assertSame('cosmicsting', $matches[0]['id'], 'Overlay entry should take ownership of the merged remediation state id.');
        assertSame('critical', $matches[0]['severity'], 'Overlay severity should be able to raise the base OSV severity.');
        assertSame('composer-update', $matches[0]['selected_remediation']['type'], 'Merged match should keep the overlay remediation.');
        assertSame('osv+registry', $matches[0]['source'], 'Merged match should record that it combines OSV and registry data.');
    },
    'matcher_falls_back_to_overlay_entry_when_osv_is_unavailable' => static function (): void {
        $project = [
            'edition_package' => 'magento/product-community-edition',
            'version' => '2.4.6-p5',
        ];
        $registry = [[
            'id' => 'cosmicsting',
            'cve' => 'CVE-2024-34102',
            'aliases' => ['GHSA-263x-hfm2-qh28'],
            'title' => 'CosmicSting',
            'severity' => 'critical',
            'description' => 'Magento-specific overlay details',
            'detection_source' => 'osv-overlay',
            'report_mode' => 'augment',
            'affected_versions' => [
                'magento/product-community-edition' => '>=2.4.6 <2.4.6-p6',
            ],
            'remediations' => [[
                'phase' => 'official',
                'type' => 'composer-update',
                'condition' => 'always',
                'packages' => [
                    'magento/product-community-edition' => '2.4.6-p6',
                ],
            ]],
        ]];

        $matcher = new Matcher();
        $matches = $matcher->match($project, [], $registry, ['vulnerabilities' => []], 'medium');

        assertSame(1, count($matches), 'Overlay entries should still surface when OSV is unavailable.');
        assertSame('registry', $matches[0]['source'], 'Fallback overlay matches should be sourced from the registry.');
    },
    'matcher_adds_registry_only_day_zero_entry' => static function (): void {
        $project = [
            'edition_package' => 'magento/product-community-edition',
            'version' => '2.4.6-p5',
        ];
        $registry = [[
            'id' => 'pending-day-zero',
            'title' => 'Day Zero Placeholder',
            'severity' => 'critical',
            'description' => 'Standalone day-zero advisory.',
            'detection_source' => 'magesec-only',
            'affected_versions' => [
                'magento/product-community-edition' => '>=2.4.6 <2.4.6-p6',
            ],
            'remediations' => [[
                'phase' => 'interim',
                'type' => 'patch',
                'condition' => 'always',
            ]],
        ]];

        $matcher = new Matcher();
        $matches = $matcher->match($project, [], $registry, ['vulnerabilities' => []], 'low');

        assertSame(1, count($matches), 'Matcher should still surface MageSec-only registry entries when OSV has no matching advisory.');
        assertSame('registry', $matches[0]['source'], 'Day-zero entries should be sourced from the supplemental registry.');
    },
    'sarif_generator_uses_match_package_coordinates' => static function (): void {
        $generator = new SarifGenerator();
        $sarif = $generator->generate([
            'edition_package' => 'magento/product-community-edition',
            'version' => '2.4.6-p5',
            'composer_lock_path' => __DIR__ . '/fixtures/opensource-vulnerable/composer.lock',
        ], [[
            'cve' => 'CVE-2026-0001',
            'title' => 'Fixture advisory',
            'severity' => 'high',
            'cvss' => null,
            'description' => 'Fixture details',
            'impact' => [],
            'references' => [],
            'selected_remediation' => null,
            'package_name' => 'vendor/package',
            'package_version' => '1.2.3',
        ]], 'MageSec');

        assertTrue(str_contains($sarif['runs'][0]['results'][0]['message']['text'], 'vendor/package 1.2.3 is affected'), 'SARIF output should use the matched package coordinates when available.');
    },
    'issue_manager_renders_status_table' => static function (): void {
        $manager = new IssueManager(new GitHubClient(''));
        $body = $manager->renderBody(
            [
                'edition' => 'opensource',
                'edition_package' => 'magento/product-community-edition',
                'version' => '2.4.6-p5',
            ],
            [[
                'cve' => 'CVE-2024-34102',
                'title' => 'CosmicSting',
                'severity' => 'critical',
                'selected_remediation' => ['type' => 'composer-update'],
            ]]
        );

        assertTrue(str_contains($body, '<!-- magesec-status -->'), 'Issue body should contain the status marker.');
        assertTrue(str_contains($body, '| CVE-2024-34102 | CosmicSting | CRITICAL | Official patch available |'), 'Issue body should render the vulnerability table row.');
    },
];

$failures = [];

foreach ($tests as $name => $test) {
    try {
        $test();
        fwrite(STDOUT, sprintf("[PASS] %s\n", $name));
    } catch (Throwable $exception) {
        $failures[] = sprintf('[FAIL] %s: %s', $name, $exception->getMessage());
    }
}

if ($failures !== []) {
    foreach ($failures as $failure) {
        fwrite(STDERR, $failure . PHP_EOL);
    }
    exit(1);
}

fwrite(STDOUT, sprintf("%d tests passed.\n", count($tests)));