# Changelog

## v1.0.0 - K1Wi Framework

- Promoted K1Wi from release candidate to stable v1.0.0.
- Added lowercase LYZER mode support and regression coverage.
- Hardened CLI dispatch, terminal-width handling, PIECALC symbol listing, and regression test targets.
- Confirmed normal regression suite passes 72/72 tests.

## v0.99 RC1 - K1Wi

### Added
- Added centralized version banner through `include/version.h`.
- Added `opus --version` and `opus version` output for release tracking.
- Added regression coverage for VERSION output.
- Added RSA CLI support through `opus rsa <rsa_file>`.
- Added ELF CLI support through `opus elf <binary>`.
- Added PIECALC CLI regression coverage.
- Added LYZER CLI support for full image/file forensic scans.
- Added negative CLI behavior tests.

### Improved
- Expanded regression coverage for STRING, EXTRACT, LYZER, ENTROPY, ELF, PIECALC, RSA, and VERSION.
- Improved CLI argument handling for missing inputs.
- Cleaned compiler warnings.
- Verified sanitizer build with regression suite.

### Fixed
- Fixed STRING command argument parsing.
- Fixed EXTRACT recursive dispatch.
- Fixed LYZER CLI dispatch.
- Fixed ENTROPY CLI dispatch.
- Fixed ELF CLI dispatch.
- Fixed RSA CLI dispatch.
- Fixed regression assertions using fixed-string matching.

### Status
- Clean build: passing.
- Regression suite: passing.
- Sanitizer run: passing.
