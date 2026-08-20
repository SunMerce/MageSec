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

### If SARIF upload is not available

`upload-sarif` requires GitHub code scanning: free on public repositories, but requires GitHub Advanced Security on private ones. It also needs the `security-events: write` permission, which is never granted to workflows running from fork pull requests.

If the upload fails with "Advanced Security must be enabled" or "Resource not accessible by integration", keep the results as a workflow artifact instead (the job summary is always written regardless):

```yaml
      - uses: owner/magesec@v1
        id: magesec

      - uses: github/codeql-action/upload-sarif@v3
        if: always() && github.event.pull_request.head.repo.full_name == github.repository
        with:
          sarif_file: ${{ steps.magesec.outputs.sarif_file }}

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: magesec-results
          path: ${{ steps.magesec.outputs.sarif_file }}
```

No pull request is required for code scanning — uploads work on `push` and `pull_request` events alike, as long as the permission and plan requirements above are met.

## Automatic remediation pull requests

For private repositories without code scanning, MageSec can instead open a pull request that applies the fix directly. When a matched registry advisory has a `composer-update` remediation, the action pins the patched version in `composer.json`, regenerates `composer.lock` (when Composer can resolve in the scan environment), pushes a `magesec/security-fix-*` branch, and opens a PR labelled `security`:

```yaml
permissions:
  contents: write
  pull-requests: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: owner/magesec@v1
        with:
          auto_pr: "true"
```

No PAT or extra secrets are required — the action defaults to the built-in `GITHUB_TOKEN`. One caveat: pull requests opened by `GITHUB_TOKEN` do not trigger further workflow runs (GitHub's anti-recursion rule), so CI will not start automatically on the remediation PR. If you need CI on those PRs, pass a PAT via `github_token` instead.

- Re-running the scan reuses the existing branch/PR instead of opening duplicates.
- Fork pull requests never receive write tokens; the PR step is skipped gracefully there.
- When multiple advisories touch the same package, the PR converges on the highest target version.
- Advisories whose remediation is a manual patch (not a composer update) are reported but not auto-applied.

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `composer_path` | `.` | Path from the repository root to the Magento composer files. |
| `severity_threshold` | `low` | Minimum severity to include in SARIF and the action summary. |
| `use_osv` | `true` | Query OSV for baseline Composer vulnerability data before applying MageSec overlays. |
| `osv_api_url` | `https://api.osv.dev/v1` | Base OSV API URL. |
| `registry_repository` | `""` | Optional `owner/repo` that contains registry YAML files. |
| `registry_ref` | `""` | Branch, tag, or SHA to fetch from `registry_repository`. When empty, the bundled registry is used. |
| `github_token` | `${{ github.token }}` | Only needed when `registry_repository` points to a private repository, or to override the token used for `auto_pr`. |
| `write_summary` | `true` | Write a human-readable summary to the workflow job. |
| `auto_remediate` | `false` | Apply available composer-update remediations to `composer.json`/`composer.lock` in the workspace. |
| `auto_pr` | `false` | Push remediations to a `magesec/*` branch and open a PR labelled `security`. Implies `auto_remediate`. |
| `pr_label` | `security` | Label applied to automatically opened remediation pull requests. |
| `base_branch` | `""` | Branch the remediation PR targets. Defaults to the PR base branch or the current ref. |

## Outputs

| Output | Description |
| --- | --- |
| `sarif_file` | Relative path to the generated SARIF file. |
| `vulnerabilities_found` | Number of matched vulnerabilities at or above the configured threshold. |
| `pr_url` | URL of the remediation pull request, when `auto_pr` opened or reused one. |

## Development

Run the test suite:

```sh
php tests/run.php
```
