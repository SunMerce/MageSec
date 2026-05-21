<?php

declare(strict_types=1);

require __DIR__ . '/bootstrap.php';

use MageSec\Detector;
use MageSec\GitHubClient;
use MageSec\IssueManager;
use MageSec\Matcher;
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
        $matches = $matcher->match($project, $registry, ['vulnerabilities' => []], 'high');

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
        $matches = $matcher->match($project, $registry, [
            'vulnerabilities' => [
                'cosmicsting' => ['phase' => 'interim'],
            ],
        ], 'low');

        assertSame('official', $matches[0]['selected_remediation']['phase'], 'Matcher should prefer the official replacement when an interim fix is already recorded.');
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