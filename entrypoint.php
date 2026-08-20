<?php

declare(strict_types=1);

spl_autoload_register(static function (string $class): void {
    $prefix = 'MageSec\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }

    $relativeClass = substr($class, strlen($prefix));
    $path = __DIR__ . '/src/' . str_replace('\\', '/', $relativeClass) . '.php';
    if (is_file($path)) {
        require $path;
    }
});

use MageSec\Detector;
use MageSec\GitHubClient;
use MageSec\Json;
use MageSec\Matcher;
use MageSec\OsvClient;
use MageSec\PullRequestManager;
use MageSec\RegistryLoader;
use MageSec\RemediationPlanner;
use MageSec\SarifGenerator;
use MageSec\StateManager;
use MageSec\SummaryWriter;

function inputBool(string $name, bool $default): bool
{
    $value = getenv($name);
    if ($value === false || $value === '') {
        return $default;
    }

    $normalized = strtolower(trim($value));
    return in_array($normalized, ['1', 'true', 'yes', 'on'], true);
}

function writeOutput(string $name, string $value): void
{
    $outputPath = getenv('GITHUB_OUTPUT');
    if ($outputPath === false || $outputPath === '') {
        return;
    }

    file_put_contents($outputPath, sprintf("%s=%s\n", $name, $value), FILE_APPEND);
}

try {
    $workspace = getenv('GITHUB_WORKSPACE') ?: getcwd();
    $actionPath = getenv('GITHUB_ACTION_PATH') ?: __DIR__;

    $inputs = [
        'composer_path' => trim((string) (getenv('INPUT_COMPOSER_PATH') ?: '.'), '/'),
        'severity_threshold' => strtolower((string) (getenv('INPUT_SEVERITY_THRESHOLD') ?: 'low')),
        'use_osv' => inputBool('INPUT_USE_OSV', true),
        'osv_api_url' => (string) (getenv('INPUT_OSV_API_URL') ?: 'https://api.osv.dev/v1'),
        'registry_repository' => (string) (getenv('INPUT_REGISTRY_REPOSITORY') ?: ''),
        'registry_ref' => (string) (getenv('INPUT_REGISTRY_REF') ?: ''),
        'github_token' => (string) (getenv('INPUT_GITHUB_TOKEN') ?: getenv('GITHUB_TOKEN') ?: ''),
        'write_summary' => inputBool('INPUT_WRITE_SUMMARY', true),
        'auto_remediate' => inputBool('INPUT_AUTO_REMEDIATE', false),
        'auto_pr' => inputBool('INPUT_AUTO_PR', false),
        'pr_label' => (string) (getenv('INPUT_PR_LABEL') ?: 'security'),
        'base_branch' => (string) (getenv('INPUT_BASE_BRANCH') ?: getenv('GITHUB_BASE_REF') ?: getenv('GITHUB_REF_NAME') ?: 'main'),
    ];

    $stateManager = new StateManager();
    $state = $stateManager->load($workspace);

    $detector = new Detector();
    $project = $detector->detect($workspace, $inputs['composer_path']);

    $client = new GitHubClient($inputs['github_token']);
    $osvFindings = [];
    if ($inputs['use_osv']) {
        try {
            $osvClient = new OsvClient($inputs['osv_api_url']);
            $osvFindings = $osvClient->queryProject($project);
        } catch (Throwable $exception) {
            fwrite(STDERR, '[MageSec] OSV baseline unavailable: ' . $exception->getMessage() . PHP_EOL);
        }
    }

    $registryLoader = new RegistryLoader($client);
    $registry = $registryLoader->load(
        $actionPath,
        $inputs['registry_repository'],
        $inputs['registry_ref']
    );

    $matcher = new Matcher();
    $matches = $matcher->match($project, $osvFindings, $registry, $state, $inputs['severity_threshold']);

    $prResult = null;
    if ($inputs['auto_remediate'] || $inputs['auto_pr']) {
        $planner = new RemediationPlanner();
        $plan = $planner->plan($project, $matches);

        if ($plan['updates'] === []) {
            $prResult = ['skipped_reason' => 'No automated composer-update remediation is available for the matched vulnerabilities.'];
        } else {
            $composerJson = $project['composer_json'];
            $applied = $planner->applyToManifest($composerJson, $plan);

            if ($applied === []) {
                $prResult = ['skipped_reason' => 'Planned packages were not found in composer.json requirements.'];
            } else {
                $composerJsonContents = Json::encodeComposerManifest($composerJson);
                file_put_contents($project['composer_json_path'], $composerJsonContents);

                $composerLockContents = null;
                $updatePackages = array_column($applied, 'package');
                $command = sprintf(
                    'cd %s && composer update --with-all-dependencies --no-install --no-interaction --no-audit --no-plugins --ignore-platform-reqs -- %s 2>&1',
                    escapeshellarg($project['root']),
                    implode(' ', array_map('escapeshellarg', $updatePackages))
                );
                exec($command, $commandOutput, $commandStatus);
                if ($commandStatus === 0 && is_file($project['composer_lock_path'])) {
                    $composerLockContents = file_get_contents($project['composer_lock_path']) ?: null;
                } else {
                    fwrite(STDERR, '[MageSec] composer update failed; PR will pin composer.json only.' . PHP_EOL);
                    fwrite(STDERR, implode("\n", $commandOutput) . PHP_EOL);
                }

                if ($inputs['auto_pr']) {
                    if ($inputs['github_token'] === '') {
                        $prResult = ['skipped_reason' => 'auto_pr requires a github_token input (or GITHUB_TOKEN) with contents:write and pull-requests:write.'];
                    } else {
                        // Fork PRs never receive write tokens; skip gracefully.
                        $headRepo = '';
                        $eventPath = getenv('GITHUB_EVENT_PATH');
                        if (is_string($eventPath) && is_file($eventPath)) {
                            $event = json_decode((string) file_get_contents($eventPath), true);
                            $headRepo = (string) ($event['pull_request']['head']['repo']['full_name'] ?? '');
                        }
                        if ($headRepo !== '' && $headRepo !== (string) getenv('GITHUB_REPOSITORY')) {
                            $prResult = ['skipped_reason' => 'Pull requests from forks cannot receive write tokens; skipping auto PR.'];
                        }
                    }

                    if ($prResult === null) {
                        $repository = (string) getenv('GITHUB_REPOSITORY');
                        $prManager = new PullRequestManager($client, $repository, $inputs['pr_label']);
                        $prResult = $prManager->open(
                            ['updates' => $applied, 'advisories' => $plan['advisories']],
                            $composerJsonContents,
                            $composerLockContents,
                            $inputs['composer_path'],
                            $inputs['base_branch']
                        );
                    }
                } else {
                    $prResult = ['skipped_reason' => 'auto_pr is disabled; composer.json was updated in the workspace only.'];
                }
            }
        }
    }

    $sarifGenerator = new SarifGenerator();
    $sarif = $sarifGenerator->generate($project, $matches, 'MageSec');

    $sarifRelativePath = 'magesec-results.sarif';
    $sarifPath = rtrim($workspace, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $sarifRelativePath;
    file_put_contents($sarifPath, json_encode($sarif, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));

    if ($inputs['write_summary']) {
        $summaryWriter = new SummaryWriter();
        $summaryWriter->write($project, $matches, $sarifRelativePath, $prResult);
    }

    writeOutput('sarif_file', $sarifRelativePath);
    writeOutput('vulnerabilities_found', (string) count($matches));
    if (is_array($prResult) && isset($prResult['url'])) {
        writeOutput('pr_url', (string) $prResult['url']);
    }
} catch (Throwable $exception) {
    fwrite(STDERR, '[MageSec] ' . $exception->getMessage() . PHP_EOL);
    exit(1);
}