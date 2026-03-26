# Changelog

All notable changes to ProxyDHCPd will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.3.2] - 2026-03-26

### Fixed
- **License file alignment**: Renamed `gpl-2.0.txt` to `LICENSE` and updated `pyproject.toml` to use the legacy `{ file = "LICENSE" }` format to support older build systems.

## [0.3.1] - 2026-03-26

### Added
- **Unified cross-distro RPM spec**: Support for both Fedora (pyproject-rpm-macros) and openSUSE (python-rpm-macros) in a single file
- **GitHub Actions workflow**: Automated PyPI publishing and GitHub Release creation on tag push

### Changed
- **Packaging hygiene**: Fixed PEP 639 license expression issues in `pyproject.toml`
- **Spec refactoring**: Implemented Fedora `%pyproject_save_files` and openSUSE standalone application patterns

## [0.3.0] - 2026-03-05

### Changed
- **CLI modernised**: Replaced `getopt` with `argparse` for proper `--help`, `--version`, `--config`, `--daemon`, and `--proxy-only` flags
- **Single source of truth versioning**: `proxydhcpd.__version__` now drives both `pyproject.toml` and `--version`
- **Removed Python 2 compatibility shims** from `proxyconfig.py`
- **Hardened `.gitignore`** to exclude `.coverage`, `htmlcov/`, and `.pytest_cache/`
- **Normalised `proxy.ini`** line endings to LF

### Added
- `MANIFEST.in` for complete source distributions
- `CHANGELOG.md` (this file)
- PyPI classifiers and project URLs in `pyproject.toml`
- `%license` and `%doc` directives in RPM spec

## [0.2.0] - 2026-02-26

### Changed
- Full port to Python 3 with `pyproject.toml` build system
- Added embedded fork of `pydhcplib` (pure Python, zero external dependencies)
- Systemd service unit with security hardening (`DynamicUser`, `AmbientCapabilities`, `ProtectSystem=strict`)
- Test suite with 5 iPXE routing scenarios using `pytest` + `unittest.mock`
- RFC 4578 architecture whitelisting (Option 93) with native iPXE chainloading (Option 77)

[0.3.2]: https://github.com/gmoro/proxyDHCPd/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/gmoro/proxyDHCPd/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/gmoro/proxyDHCPd/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/gmoro/proxyDHCPd/releases/tag/v0.2.0
