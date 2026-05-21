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
use MageSec\IssueManager;
use MageSec\Matcher;
use MageSec\PrManager;
use MageSec\RegistryLoader;
use MageSec\Remediator;
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
        'registry_repository' => (string) (getenv('INPUT_REGISTRY_REPOSITORY') ?: ''),
        'registry_ref' => (string) (getenv('INPUT_REGISTRY_REF') ?: ''),
        'github_token' => (string) (getenv('INPUT_GITHUB_TOKEN') ?: getenv('GITHUB_TOKEN') ?: ''),
        'auto_remediate' => inputBool('INPUT_AUTO_REMEDIATE', false),
        'auto_pr' => inputBool('INPUT_AUTO_PR', false),
        'auto_issue' => inputBool('INPUT_AUTO_ISSUE', false),
        'write_summary' => inputBool('INPUT_WRITE_SUMMARY', true),
    ];

    $stateManager = new StateManager();
    $state = $stateManager->load($workspace);

    $detector = new Detector();
    $project = $detector->detect($workspace, $inputs['composer_path']);

    $client = new GitHubClient($inputs['github_token']);
    $registryLoader = new RegistryLoader($client);
    $registry = $registryLoader->load(
        $actionPath,
        $inputs['registry_repository'],
        $inputs['registry_ref']
    );

    $matcher = new Matcher();
    $matches = $matcher->match($project, $registry, $state, $inputs['severity_threshold']);

    $sarifGenerator = new SarifGenerator();
    $sarif = $sarifGenerator->generate($project, $matches, 'MageSec');

    $sarifRelativePath = 'magesec-results.sarif';
    $sarifPath = rtrim($workspace, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $sarifRelativePath;
    file_put_contents($sarifPath, json_encode($sarif, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));

    $remediationResult = [
        'planned' => [],
        'changed_files' => [],
        'warnings' => [],
    ];

    if ($inputs['auto_remediate'] && $matches !== []) {
        $remediator = new Remediator($actionPath, $stateManager);
        $remediationResult = $remediator->apply($workspace, $project, $matches, $state);
        $state = $stateManager->load($workspace);
    }

    $prResult = [
        'created' => 0,
        'number' => null,
        'url' => null,
        'skipped_reason' => null,
    ];

    if ($inputs['auto_pr'] && $remediationResult['changed_files'] !== []) {
        $prManager = new PrManager($client);
        $prResult = $prManager->createOrUpdateAggregatePr($workspace, $matches, $inputs['github_token']);
    }

    $issueResult = [
        'created' => 0,
        'number' => null,
        'url' => null,
        'skipped_reason' => null,
    ];

    if ($inputs['auto_issue']) {
        $issueManager = new IssueManager($client);
        $issueResult = $issueManager->sync($project, $matches, $inputs['github_token']);
    }

    if ($inputs['write_summary']) {
        $summaryWriter = new SummaryWriter();
        $summaryWriter->write($project, $matches, $sarifRelativePath, $remediationResult, $prResult, $issueResult);
    }

    writeOutput('sarif_file', $sarifRelativePath);
    writeOutput('vulnerabilities_found', (string) count($matches));
    writeOutput('remediations_planned', (string) count(array_filter($matches, static fn (array $match): bool => $match['selected_remediation'] !== null)));
    writeOutput('pull_requests_created', (string) $prResult['created']);
    writeOutput('status_issue_url', (string) ($issueResult['url'] ?? ''));
} catch (Throwable $exception) {
    fwrite(STDERR, '[MageSec] ' . $exception->getMessage() . PHP_EOL);
    exit(1);
}