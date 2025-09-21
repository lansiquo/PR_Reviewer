# Changelog
All notable changes to this project will be documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v0.1.0] - 2025-09-21
### Added
- Initial tag and first protected merge baseline.

## [v0.1.1] - 2025-09-21
### Added
- Repository foundations: `LICENSE` (MIT), `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`.
- **Makefile** targets: `setup`, `lint`, `test`, `scan`, `protect`, `unprotect`, `release`.
- **Branch protection config** (`.github/branch-protection/protection.json`) and `make protect` to apply it.
- **CODEOWNERS** for future review routing.

### Changed
- Enforced **admins included**, **no force pushes**, **no deletions** on `main`.


## [v0.1.2] - 2025-09-21
### Added
- **CI security gate**: GitHub Actions workflow **RobinSec / RobinSec** using `semgrep ci` (PR-aware), with
  explicit permissions, concurrency cancel, job timeout, and SARIF upload to the Security tab.
- **Semgrep ruleset**: initial custom rules (`py.dangerous.eval`, `py.subprocess.shell-true`, plus
  org rules like `py.yaml.unsafe-load` and `py.crypto.weak-random`), alongside curated packs
  (`p/security-audit`, `p/secrets`).
- **.semgrepignore** to skip `node_modules/`, `dist/`, `venv/`, and other noise.
- **PR template** with a minimal security checklist.

### Changed
- **Branch protection** now requires the single check **“RobinSec / RobinSec”** (removed the old
  `pr-security-review / semgrep` requirement to avoid duplicate/ghost checks).
- Tuned protection for **strict status checks**, **linear history**, and **conversation resolution**.

### Fixed
- Resolved hanging checks by aligning the required context to the workflow/job name and ensuring the
  job always completes (timeouts + `semgrep ci`).

#### I came through a merge