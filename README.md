# K1Wi Framework

K1Wi is a Linux-based reverse engineering, cryptanalysis, digital forensics, and file analysis framework written in C.

The project combines forensic analysis, archive extraction, cryptanalysis, binary inspection, and reverse engineering utilities into a single command-line toolkit.

## Features

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

Build:

```bash
make
```

Run:

```bash
./bin/opus
```

## Quick Start

View available commands:

```bash
./bin/opus HELP
./bin/opus MENU
```

Analyze a string:

```bash
./bin/opus STRING SGVsbG8=
```

Analyze a file:

```bash
./bin/opus ENTROPY sample.bin
```

Inspect an ELF binary:

```bash
./bin/opus ELFINFO -IN ./bin/opus
```

Run image forensics:

```bash
./bin/opus LYZER image.jpg ALL
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

K1Wi has successfully completed clean-room build validation and regression testing and is approaching the v1.0 release milestone.

## License


K1Wi is released under the MIT License.

Copyright (c) 2026 Gregory B. Novak

See the LICENSE file for full details.
