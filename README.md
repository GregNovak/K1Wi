# K1Wi Framework

K1Wi is a Linux-based reverse engineering, cryptanalysis, digital forensics, and file analysis framework written in C.

The project combines digital forensics, archive extraction, cryptanalysis, binary inspection, and reverse engineering utilities into a unified command-line framework.

## Features

K1Wi provides a collection of reverse engineering, digital forensics,
cryptanalysis, binary analysis, and file investigation tools designed for
security researchers, students, and CTF participants.

Major capabilities are grouped into the categories below.

### Forensics

* LYZER forensic file and image analysis
* STRING intelligence and decoding
* SEARCH file pattern analysis
* Entropy analysis
* Embedded file detection
* File carving
* JPEG forensic analysis
* Magic byte detection

### Extraction

* Recursive archive extraction
* Embedded file recovery
* Extraction logging

### Cryptanalysis

* Vigenère cipher analysis
* Substitution cipher solving
* RSA cryptanalysis

  * RSA-FACTOR (Fermat / Classical)
  * RSA-RHO (Pollard Rho)
  * RSA-ECM (Elliptic Curve Method)
  * RSA-WIENER
  * RSA-SMALL-E
  * RSA-KNOWNPQ
  * RSA-CHECKPQ
  * RSA-DFROMPQ
  * RSA-MINI

### Binary Analysis

* ELF inspection
* PIE base calculations
* Runtime address analysis
* Symbol analysis

  * ELFINFO
  * PIECALC
  * PIETIME

### Utility

* Integrated HELP system
* Command menu system
* MD5 and SHA-256 utilities
* Secure delete operations
* Bounded filesystem wipe controls

## Build

Requirements:

* GCC or Clang
* libgmp-dev
* libssl-dev
* libncurses-dev
* libjpeg-dev

Install dependencies (Ubuntu/Debian):

```bash
sudo apt install build-essential libgmp-dev libssl-dev libncurses-dev libjpeg-dev
```

Build:

```bash
make
```

Clean build:

```bash
make clean
make
```

Run:

```bash
./bin/k1wi
```

## Quick Start

View available commands:

```bash
./bin/k1wi HELP
./bin/k1wi MENU
```

Analyze a string:

```bash
./bin/k1wi STRING SGVsbG8=
```

Analyze a file:

```bash
./bin/k1wi ENTROPY sample.bin
```

Inspect an ELF binary:

```bash
./bin/k1wi ELFINFO -IN ./bin/k1wi
```

Run image forensics:

```bash
./bin/k1wi LYZER image.jpg ALL
```

## Testing

Run the regression suite:

```bash
./tests/run_regression.sh
```

Current regression status:

```text
PASS: 69
FAIL: 0
SKIP: 0
```
Validated using a clean-room build and full regression suite execution.

## Safety

Some commands operate on live filesystems and user data.

WIPEFS refuses destructive mode unless explicit safety controls are supplied:

```bash
WIPEFS <path> --max-bytes <N> --yes
```

Use dry-run mode whenever possible:

```bash
WIPEFS <path> --dry-run
```

Always test destructive operations inside disposable directories before use on production systems.

## Status

Current Version: v0.99 RC1

Release Status: Release Candidate

The project has completed clean-room build validation and currently passes all regression tests (69/69).

## License

K1Wi is released under the MIT License.

Copyright (c) 2026 Gregory B. Novak

See the LICENSE file for full details.
