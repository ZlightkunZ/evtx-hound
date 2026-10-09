# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-10-09
### Added
- Multi-format export engine: full support for CSV output (`--format csv`) alongside JSON.
- Added comprehensive unit tests for CSV streaming serialization.
- Enhanced CLI arguments with explicit format flags.

## [0.1.1] - 2026-10-09
### Added
- Standard `pyproject.toml` distribution configuration for PyPI.
- Enhanced SIEM JSON formatting schema for downstream ingestion.
- Pre-commit type checking integration via `mypy`.

### Fixed
- Handled edge-case `PermissionError` when parsing locked system `.evtx` files.

## [0.1.0] - 2026-10-08
### Added
- Initial release of the `EvtxAnalyzer` core engine.
- Detection logic for parent-child LOLBin anomalies (Winword -> PowerShell).
- Comprehensive unit test suite with `pytest`.
- Automated GitHub Actions secure CI/CD pipeline (`bandit`, `flake8`, `mypy`).
- Initial STRIDE Threat Model (`THREAT_MODEL.md`) and Security Policy (`SECURITY.md`).
