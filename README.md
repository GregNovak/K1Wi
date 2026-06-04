# K1Wi Framework

K1Wi is a Linux-based reverse engineering, cryptanalysis, digital forensics, and file analysis framework written in C.

The project combines forensic analysis, archive extraction, cryptanalysis, binary inspection, and reverse engineering utilities into a single command-line toolkit.

## Features

### Forensics

* LYZER forensic file and image analysis
* Entropy analysis
* Embedded file detection
* File carving
* JPEG forensic analysis
* String intelligence

### Extraction

* Recursive archive extraction
* Embedded file recovery
* Extraction logging

### Cryptanalysis

* Vigenère cipher analysis
* Substitution cipher solving
* RSA cryptanalysis

  * Fermat factorization
  * Pollard Rho
  * Wiener attack
  * Small exponent attacks

### Binary Analysis

* ELF inspection
* PIE base calculations
* Symbol analysis

## Build

Requirements:

* GCC or Clang
* GMP
* OpenSSL
* ncurses
* libjpeg

Build:

```bash
make
```

Run:

```bash
./bin/opus
```

## Testing

Run the regression suite:

```bash
./tests/run_regression.sh
```

Current regression status:

```text
PASS: 31
FAIL: 0
```

## Status

Current Version: v0.99 RC1

K1Wi is under active development and approaching the 1.0 release milestone.

## License

License to be determined.
