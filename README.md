# MageSec

Scan Magento composer manifests against a curated vulnerability registry (plus an optional OSV baseline) and emit SARIF results and a workflow job summary.

MageSec is scan-only: it never modifies your repository and does not require a GitHub token for normal use.

## Usage

```yaml
name: magesec
on: [push, pull_request]

permissions:
  security-events: write # only needed for the upload-sarif step

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: owner/magesec@v1
        id: magesec

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: ${{ steps.magesec.outputs.sarif_file }}
```

No `github_token` input is required. Scanning, SARIF generation, and the job summary all work without any credentials.

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `composer_path` | `.` | Path from the repository root to the Magento composer files. |
| `severity_threshold` | `low` | Minimum severity to include in SARIF and the action summary. |
| `use_osv` | `true` | Query OSV for baseline Composer vulnerability data before applying MageSec overlays. |
| `osv_api_url` | `https://api.osv.dev/v1` | Base OSV API URL. |
| `registry_repository` | `""` | Optional `owner/repo` that contains registry YAML files. |
| `registry_ref` | `""` | Branch, tag, or SHA to fetch from `registry_repository`. When empty, the bundled registry is used. |
| `github_token` | `""` | Only needed when `registry_repository` points to a private repository. Use `${{ secrets.GITHUB_TOKEN }}` with `contents: read` permission. |
| `write_summary` | `true` | Write a human-readable summary to the workflow job. |

## Outputs

| Output | Description |
| --- | --- |
| `sarif_file` | Relative path to the generated SARIF file. |
| `vulnerabilities_found` | Number of matched vulnerabilities at or above the configured threshold. |

## Development

Run the test suite:

```sh
php tests/run.php
```
