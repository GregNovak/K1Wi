# Chapter 1: What Is K1Wi?

## Introduction

K1Wi is an integrated cybersecurity analysis framework that combines reverse engineering, digital forensics, cryptanalysis, binary analysis, and Capture-The-Flag (CTF) tooling into a unified command-line environment.

The goal of K1Wi is to provide security professionals, students, researchers, and enthusiasts with a single toolkit capable of analyzing files, binaries, encoded data, cryptographic artifacts, and forensic evidence without requiring multiple disconnected utilities.

Unlike many specialized tools that focus on only one discipline, K1Wi brings together capabilities from several cybersecurity domains. A user may extract files from an archive, inspect a Linux executable, analyze hidden data within an image, evaluate cryptographic material, calculate Position Independent Executable (PIE) offsets, and perform string intelligence analysis from the same framework.

## Mission

The mission of K1Wi is to provide practical cybersecurity analysis capabilities through a lightweight, transparent, and extensible platform.

K1Wi is designed to help users:

* Analyze suspicious files and artifacts
* Perform reverse engineering tasks
* Conduct digital forensic investigations
* Solve cryptographic and CTF challenges
* Inspect executable binaries
* Identify encoded, hidden, or suspicious data
* Learn cybersecurity concepts through hands-on experimentation

## Target Audience

K1Wi is intended for:

* Cybersecurity students
* Capture-The-Flag competitors
* Security researchers
* Reverse engineers
* Malware analysts
* Digital forensic investigators
* Incident responders
* Hobbyists and self-directed learners

No advanced programming knowledge is required to begin using K1Wi, although users with experience in operating systems, networking, programming, and information security will benefit from the framework's advanced capabilities.

## Design Philosophy

K1Wi is built around several core principles:

### Simplicity

Common tasks should require minimal commands and configuration.

### Transparency

Analysis results should be understandable and traceable. K1Wi attempts to explain findings rather than simply report them.

### Practicality

Features are selected based on real-world usefulness for security practitioners, students, and challenge solvers.

### Modularity

Capabilities are organized into independent modules that can evolve without affecting the entire framework.

### Education

K1Wi serves as both an operational toolkit and a learning platform for understanding cybersecurity concepts.

## Core Capability Areas

K1Wi currently provides functionality in the following areas:

### String Intelligence

Detection and analysis of encoded, encrypted, structured, and suspicious strings.

### Digital Forensics

Entropy analysis, file extraction, file carving, embedded signature detection, and artifact discovery.

### Image Analysis

JPEG forensic analysis, entropy heatmaps, RS steganography detection, Huffman fingerprinting, and DCT coefficient analysis.

### Binary Analysis

ELF inspection, symbol enumeration, dependency analysis, and executable metadata extraction.

### Reverse Engineering

PIE base calculations, symbol resolution, address translation, and runtime analysis support.

### Cryptanalysis

RSA challenge analysis, factorization support, key inspection, and educational cryptographic tooling.

### CTF Support

Integrated workflows that assist with challenge analysis, artifact inspection, and investigative problem solving.

## Project Status

Current Release:

Version: 1.0.0
Current Development Status: Stable

K1Wi continues to evolve through additional analysis modules, expanded testing coverage, improved documentation, and user-driven enhancements.

The remainder of this manual describes installation, operation, workflows, command references, troubleshooting procedures, and development guidance for the K1Wi Framework.

# Chapter 2: Installation and Building K1Wi

## Overview

This chapter describes the process of installing dependencies, compiling K1Wi from source, running tests, and verifying a successful installation.

K1Wi is currently developed and tested on Ubuntu Linux and other Debian-based distributions. The build system uses GNU Make and the Clang compiler.

## System Requirements

Minimum recommended system:

* Ubuntu 22.04 LTS or newer
* 4 GB RAM
* 500 MB free disk space
* GCC or Clang compiler
* GNU Make

Recommended system:

* Ubuntu 24.04 LTS
* 8 GB RAM or greater
* Clang compiler
* Git
* AddressSanitizer support

## Required Dependencies

K1Wi depends on several external libraries.

Install all required packages using:

```bash
sudo apt update

sudo apt install \
    build-essential \
    clang \
    make \
    libgmp-dev \
    libjpeg-dev \
    libssl-dev \
    libncurses-dev
```

### Dependency Purpose

| Package        | Purpose                                      |
| -------------- | -------------------------------------------- |
| clang          | Primary compiler                             |
| make           | Build system                                 |
| libgmp-dev     | Large integer arithmetic used by RSA modules |
| libjpeg-dev    | JPEG analysis and steganography modules      |
| libssl-dev     | Cryptographic functions                      |
| libncurses-dev | Terminal user interface support              |

## Obtaining the Source Code

Clone the repository:

```bash
git clone https://github.com/GregNovak/K1Wi.git
cd K1Wi
```

Or extract a source archive:

```bash
tar -xf k1wi-source.tar.gz
cd software
```

## Directory Structure

A typical K1Wi source tree contains:

```text
software/
├── bin/
├── build/
├── Manuals/
├── tests/
├── testdata/
├── include/
├── *.c
├── *.h
├── makefile
└── README.md
```

### Directory Descriptions

| Directory | Purpose                      |
| --------- | ---------------------------- |
| bin       | Compiled executables         |
| build     | Object files                 |
| Manuals   | User documentation           |
| tests     | Regression test suite        |
| testdata  | Sample files used by testing |
| include   | Shared header files          |

## Building K1Wi

### Clean Build

Remove previous build artifacts:

```bash
make clean
```

Compile the framework:

```bash
make
```

Expected output:

```text
[CC] ...
[LINK] bin/k1wi
```

Upon successful completion, the executable will be located at:

```bash
bin/k1wi
```

## Build Modes

### Debug Build

Used during development.

```bash
make debug
```

Debug builds include symbols and additional diagnostic information.

### Release Build

Used for production releases.

```bash
make release
```

Release builds prioritize optimization and reduced binary size.

### Sanitizer Build

Used to detect memory safety issues.

```bash
make sanitize
```

Sanitizer builds help identify:

* Buffer overflows
* Use-after-free bugs
* Invalid memory access
* Memory corruption

### Thread Sanitizer Build

Used to detect race conditions in multithreaded code.

```bash
make tsan
```

## Verifying Installation

After compilation completes, verify that k1wi starts correctly.

### Display Version Information

```bash
./bin/k1wi --version
```

Expected output:

```text
K1Wi Framework v1.0.0
Release Name: K1Wi
Build Date: ...
Build Time: ...
```

### Display Help Information

```bash
./bin/k1wi help
```

This command should display the available modules and command categories.

## Running Regression Tests

K1Wi includes an automated regression suite.

Execute:

```bash
./tests/run_regression.sh
```

A successful run will end with output similar to:

```text
============================================================
REGRESSION TEST SUMMARY
============================================================
PASS: 69
FAIL: 0
SKIP: 0
```

Any failures should be investigated before deploying or releasing K1Wi.

## Running Sanitizer Validation

For maximum confidence before release:

```bash
make sanitize
./tests/run_regression.sh
```

A successful run confirms that the framework operates correctly under AddressSanitizer instrumentation.

## Troubleshooting

### Missing Header Files

Error:

```text
fatal error: header.h: No such file or directory
```

Solution:

Verify that all required development packages are installed.

### Missing Libraries

Error:

```text
undefined reference to ...
```

Solution:

Verify installation of:

* libgmp-dev
* libjpeg-dev
* libssl-dev
* libncurses-dev

### Permission Denied

Error:

```text
Permission denied
```

Solution:

Verify executable permissions:

```bash
chmod +x ./bin/k1wi
```

### Build Artifacts Corrupted

Solution:

Perform a clean rebuild:

```bash
make clean
make
```

## Summary

At this point, K1Wi should compile successfully, pass regression testing, and be ready for operational use.

The next chapter introduces the Quick Start Guide and demonstrates common workflows that can be performed within the first fifteen minutes of using K1Wi.

# Chapter 3: Quick Start Guide

## Overview

This chapter introduces the most common K1Wi workflows. By the end of this chapter, users will be able to verify their installation, inspect files, analyze strings, inspect binaries, and execute the automated regression suite.

## Verify Installation

Display version information:

```bash
./bin/k1wi --version
```

Expected output:

```text
K1Wi Framework v1.0.0
Release Name: K1Wi
Build Date: ...
Build Time: ...
Integrated Reverse Engineering and Cryptanalysis Framework
```

If version information appears, the executable is functioning correctly.

## Display Available Commands

Show the built-in command reference:

```bash
./bin/k1wi help
```

This command displays the major K1Wi modules and supported workflows.

Important modules include:

* STRING
* EXTRACT
* LYZER
* ENTROPY
* ELFINFO
* PIECALC
* RSA-FACTOR

## Analyze a Simple String

Run:

```bash
./bin/k1wi STRING "hello world"
```

Example output:

```text
Length: 11
Printable: yes
Entropy: ...
Detected Type: UTF-8 text
```

K1Wi automatically attempts to identify string types and detect common encodings.

## Analyze a Suspicious String

Run:

```bash
./bin/k1wi STRING "R2d2d2d2d2d424547494e2050524956415445204b45592d"
```

K1Wi will identify this as a shifted hexadecimal encoded private key marker.

This demonstrates the framework's ability to recognize encoded artifacts commonly encountered during investigations and CTF challenges.

## Measure File Entropy

Run:

```bash
./bin/k1wi ENTROPY image.jpg
```

Example output:

```text
Global entropy: 7.638774 bits/byte
```

High entropy may indicate:

* Compression
* Encryption
* Packed executables
* Embedded payloads

## Perform a Full Forensic Scan

Run:

```bash
./bin/k1wi LYZER image.jpg ALL
```

This executes all available forensic modules, including:

* Entropy Heatmap
* RS Analysis
* Embedded Signature Detection
* File Carving
* String Intelligence
* JPEG Huffman Fingerprinting
* DCT Coefficient Analysis

This is one of the most powerful workflows within K1Wi.

## Analyze an ELF Binary

Run:

```bash
./bin/k1wi ELFINFO -IN ./bin/k1wi
```

K1Wi will display:

* ELF header information
* Program headers
* Dynamic libraries
* Symbol tables

This functionality is useful for reverse engineering and binary analysis.

## List PIE Symbols

Run:

```bash
./bin/k1wi PIECALC --bin ./bin/k1wi --list
```

This displays symbol names and offsets useful for:

* ASLR analysis
* PIE calculations
* CTF challenges
* Exploit development research

## Analyze an RSA Challenge

Run:

```bash
./bin/k1wi RSA-FACTOR testdata/rsa/rsa_61_53_e17.txt
```

Example output:

```text
RSA Input
---------
N = 3233
e = 17
c = 855

[+] p = 53
[+] q = 61

Key Recovery
------------
d = 2753

Plaintext Recovery
------------------
m = 123

Decoded ASCII:
{
```

K1Wi will:

* Factor the RSA modulus
* Recover the private exponent
* Decrypt the ciphertext
* Display the recovered plaintext

This module is intended for educational cryptography and challenge-solving workflows.

## Execute the Regression Suite

Run:

```bash
./tests/run_regression.sh
```

Expected result:

```text
PASS: 69
FAIL: 0
SKIP: 0
```

A successful run confirms that major framework functionality is operating correctly.

## Summary

You have now completed the basic K1Wi workflow and verified the installation, command system, forensic analysis modules, binary analysis modules, cryptanalysis modules, and automated testing infrastructure.

The next chapter provides a detailed reference for the STRING analysis engine.

# Chapter 4: STRING Analysis Engine

## Overview

The STRING module is K1Wi's universal string analysis engine. It is designed to identify, classify, and investigate textual data, encoded artifacts, and suspicious strings commonly encountered during cybersecurity investigations, digital forensics, reverse engineering, malware analysis, and Capture-The-Flag (CTF) challenges.

Unlike traditional string extraction utilities that simply display printable text, the STRING engine attempts to understand the content and identify patterns that may indicate encoded data, credentials, cryptographic material, URLs, email addresses, or other artifacts of interest.

## Basic Usage

Analyze a string directly:

```bash
./bin/k1wi STRING "hello world"
```

Analyze a file:

```bash
./bin/k1wi STRING --file sample.txt
```

Decode detected content:

```bash
./bin/k1wi STRING --decode "<data>"
```

## Supported Detection Types

The STRING engine currently supports detection of:

* UTF-8 text
* Printable ASCII text
* Hexadecimal strings
* Shifted hexadecimal strings
* Base64 content
* URLs
* Email addresses
* JWT artifacts
* Credential-like strings
* Encoded private key markers

Additional detectors may be added in future releases.

## Example: Plain Text

Input:

```bash
./bin/k1wi STRING "hello K1Wi"
```

Example output:

```text
Length: 10
Printable: yes
Entropy: 3.1219
Detected Type: UTF-8 text
```

Interpretation:

The input appears to be normal human-readable text and does not exhibit characteristics commonly associated with encoded or encrypted content.

## Example: Shifted Hexadecimal Private Key Marker

Input:

```bash
./bin/k1wi STRING \
"R2d2d2d2d2d424547494e2050524956415445204b45592d"
```

Example output:

```text
Detected Type: Shifted hex encoded private key
```

Interpretation:

The engine identified a shifted hexadecimal sequence that decodes to a recognizable private key header.

This capability can assist investigators in locating hidden cryptographic material embedded within files, memory dumps, archives, or challenge artifacts.

## Entropy Analysis

Every analyzed string receives an entropy measurement.

Entropy is a statistical measure of randomness.

H=-\sum p_i\log_2 p_i

General guidelines:

| Entropy | Interpretation             |
| ------- | -------------------------- |
| 0-2     | Highly repetitive          |
| 2-5     | Typical text               |
| 5-7     | Mixed or partially encoded |
| 7-8     | Compressed or encrypted    |

Entropy alone should not be used as proof of encryption or malicious activity.

## String Intelligence

When analyzing files, K1Wi attempts to identify high-value artifacts.

Examples include:

* Potential credentials
* Encoded secrets
* Private key indicators
* URLs
* Email addresses
* Suspicious encoded content

Findings are categorized according to severity and confidence.

## Limitations

The STRING module uses heuristic detection methods and may occasionally produce false positives or false negatives.

Users should validate significant findings through additional analysis.

## Summary

The STRING engine serves as the primary entry point for text-based analysis within K1Wi and is often one of the first modules used during investigations, challenge solving, and forensic workflows.

# Chapter 5: EXTRACT Engine

## Overview

The EXTRACT engine is K1Wi's recursive extraction and file-carving framework. It is designed to process archives, containers, embedded files, and nested artifacts commonly encountered during digital forensic investigations, malware analysis, incident response, and Capture-The-Flag (CTF) challenges.

Unlike traditional extraction tools that stop after processing a single archive, the EXTRACT engine can recursively process newly discovered artifacts and continue analysis through multiple layers of nesting.

The goal of the EXTRACT engine is to automate artifact discovery while maintaining visibility into the extraction process.

## Core Capabilities

The EXTRACT engine supports:

* Recursive extraction
* Archive processing
* Embedded artifact discovery
* File carving
* String intelligence integration
* Session tracking
* Branch tracking
* Extraction reporting

## Basic Usage

Extract a file:

```bash
./bin/k1wi EXTRACT sample.zip
```

Perform recursive extraction:

```bash
./bin/k1wi EXTRACT --recursive sample.zip
```

This instructs K1Wi to continue processing newly discovered files until no additional extractable content remains or the recursion limit is reached.

## Extraction Sessions

Every extraction operation is assigned a unique session identifier.

Example:

```text
EXTRACT SESSION 0001
```

The session number allows investigators to track results, correlate output directories, and maintain a record of extraction activity.

## Extraction Workflow

The EXTRACT engine performs the following high-level workflow:

1. Validate input file
2. Identify file type
3. Extract supported content
4. Perform string intelligence analysis
5. Carve embedded artifacts
6. Queue newly discovered files
7. Repeat until completion

This workflow allows K1Wi to process deeply nested structures automatically.

## Recursive Extraction

Recursive mode is one of the most powerful capabilities of the EXTRACT engine.

Example:

```bash
./bin/k1wi EXTRACT --recursive suspicious_archive.zip
```

Possible structure:

```text
archive.zip
 ├── image.jpg
 ├── document.pdf
 └── hidden.zip
      ├── notes.txt
      └── payload.bin
```

When recursion is enabled, K1Wi continues processing newly discovered archives and artifacts until the extraction tree has been exhausted.

## Output Directories

Example:

```text
carved/extract_0001/
```

Within this directory, K1Wi stores:

* Extracted files
* Carved artifacts
* Intermediate processing results
* Final output artifacts

The directory structure preserves the extraction path and investigation history.

## Branch Tracking

K1Wi tracks extraction branches to help investigators understand artifact lineage.

Example:

```text
depth_00_branch_000_final
```

This naming convention allows users to determine:

* Recursion depth
* Branch origin
* Final artifact location

Branch tracking is especially useful when processing large or heavily nested archives.

## String Intelligence Integration

During extraction, K1Wi automatically invokes STRING analysis on discovered artifacts.

Example output:

```text
[STRING] file=sample.zip ASCII=5 UTF8=0 Base64=0 URL=0 Email=0
```

This provides investigators with immediate visibility into potentially useful content without requiring separate analysis steps.

## File Carving

The EXTRACT engine can identify and recover embedded content discovered during analysis.

Potential examples include:

* ZIP archives
* JPEG images
* PDF documents
* PNG images
* GZIP streams

Recovered artifacts are automatically added to the extraction workflow.

## Example Session

Command:

```bash
./bin/k1wi EXTRACT --recursive testdata/archives/sample.zip
```

Example output:

```text
EXTRACT SESSION 0001

Target
------------------------------------------------------------
testdata/archives/sample.zip

Analysis
------------------------------------------------------------
[STRING] file=testdata/archives/sample.zip ASCII=5 UTF8=0

Output : carved/extract_0001/depth_00_branch_000_final
Files  : 2

EXTRACT COMPLETE
```

## Practical Use Cases

The EXTRACT engine is useful for:

### Malware Analysis

* Nested droppers
* Embedded payloads
* Packed archives

### Digital Forensics

* Archive examination
* Evidence collection
* Artifact recovery

### Incident Response

* Email attachment analysis
* Suspicious archive inspection
* Payload discovery

### Capture-The-Flag Challenges

* Multi-stage archive challenges
* Hidden artifact discovery
* Embedded flag recovery

## Limitations

Current limitations include:

* Recursion depth limits for safety
* Supported file types may vary by release
* Deeply nested archives may increase processing time
* False positives are possible during file carving

Users should validate significant findings independently.

## Summary

The EXTRACT engine serves as the primary artifact discovery and recursive processing component of K1Wi. By combining extraction, carving, recursion, and string intelligence into a unified workflow, the engine provides investigators with an efficient method for locating hidden or nested content.


# Chapter 6: LYZER Forensic Analysis Engine

## Overview

The LYZER engine is K1Wi's advanced forensic analysis framework. It combines multiple investigative techniques into a single workflow designed to identify hidden data, embedded content, steganography indicators, anomalous structures, and forensic artifacts within files.

LYZER was designed to provide investigators with a rapid assessment of suspicious files while preserving detailed technical information for deeper analysis.

Unlike traditional forensic tools that focus on a single technique, LYZER executes multiple analytical modules and aggregates their findings into a unified report.

## Core Analysis Modules

The LYZER engine currently includes:

| Module                       | Purpose                                  |
| ---------------------------- | ---------------------------------------- |
| Entropy Analysis             | Measures randomness                      |
| Entropy Heatmap              | Identifies localized anomalies           |
| RS Analysis                  | Detects steganographic indicators        |
| Embedded Signature Detection | Locates hidden file types                |
| File Carving                 | Recovers embedded artifacts              |
| String Intelligence          | Identifies useful textual artifacts      |
| JPEG Huffman Fingerprinting  | Detects custom Huffman tables            |
| DCT Analysis                 | Evaluates JPEG coefficient distributions |

## Basic Usage

Run all available modules:

```bash
./bin/k1wi LYZER image.jpg ALL
```

Run a specific module:

```bash
./bin/k1wi LYZER image.jpg E
```

Module selection codes are described in the following sections.

## Understanding LYZER Results

The purpose of LYZER is not to declare a file malicious.

Instead, the engine highlights anomalies that may warrant additional investigation.

Findings should be treated as indicators rather than proof.

A single anomaly is rarely sufficient to reach a conclusion.

Multiple independent findings generally increase confidence.

### Table 1 - Entropy Interpretation
| Entropy Range | Interpretation                        |
| ------------- | ------------------------------------- |
| 0.0 - 2.0     | Repetitive or mostly empty data       |
| 2.0 - 5.0     | Typical text and structured content   |
| 5.0 - 7.0     | Mixed content or moderate compression |
| 7.0 - 8.0     | Highly compressed or encrypted data   |
| 8.0           | Maximum randomness                    |

### Table 2 - RS Analysis Interpretation
| Observation                 | Possible Meaning             |
| --------------------------- | ---------------------------- |
| Balanced R/S values         | Typical image                |
| Significant R/S deviation   | Potential steganography      |
| Large flipped-group changes | Possible LSB embedding       |
| Multiple anomalies          | Increased suspicion          |
| Normal RS profile           | No strong indicator detected |



### Table 3 - Embedded Signature Types

| Signature Type | Meaning                            | Investigator Action                    |
| -------------- | ---------------------------------- | -------------------------------------- |
| ZIP            | Embedded archive detected          | Extract and inspect contents           |
| JPEG           | Embedded image detected            | Review image metadata and content      |
| PNG            | Embedded image detected            | Inspect for hidden or modified content |
| PDF            | Embedded document detected         | Review document structure and metadata |
| GZIP           | Compressed data stream detected    | Decompress and analyze recovered data  |
| ELF            | Embedded Linux executable detected | Perform binary analysis                |
| Unknown        | Unrecognized signature             | Investigate manually                   |

### Table 4 - Huffman Fingerprint Interpretation

| Observation             | Possible Meaning                          |
| ----------------------- | ----------------------------------------- |
| Standard Huffman Tables | Typical JPEG generated by common software |
| Custom Huffman Tables   | Possible recompression or modification    |
| Uncommon Fingerprint    | Non-standard processing pipeline          |
| Multiple Variations     | Potential editing history                 |
| Highly Anomalous Tables | May warrant further forensic review       |

### Table 5 - DCT Coefficient Interpretation

| Observation                       | Possible Meaning                  |
| --------------------------------- | --------------------------------- |
| Natural Distribution              | Typical JPEG compression          |
| Excessive Zero Coefficients       | Heavy compression                 |
| Unusual Frequency Patterns        | Possible manipulation             |
| Localized Anomalies               | Potential embedded content        |
| Significant Statistical Deviation | Requires additional investigation |

### Table 6 - LYZER Confidence Levels

| Confidence Level | Description                                      |
| ---------------- | ------------------------------------------------ |
| Low              | Minor anomaly detected                           |
| Moderate         | Multiple indicators present                      |
| High             | Strong forensic indicators observed              |
| Very High        | Multiple independent anomalies support suspicion |
| Critical         | Significant evidence requiring immediate review  |

### Table 7 - Recommended Investigator Actions

| Finding Type                 | Recommended Action                          |
| ---------------------------- | ------------------------------------------- |
| High Entropy Region          | Inspect for compression or encryption       |
| Embedded Signature           | Extract and analyze recovered file          |
| RS Analysis Alert            | Investigate possible steganography          |
| Suspicious Strings           | Review decoded content                      |
| Custom Huffman Tables        | Examine image editing history               |
| Multiple Concurrent Findings | Perform full forensic review                |
| No Significant Findings      | Document results and continue investigation |

# Chapter 9: RSA Analysis Tools

## Overview

K1Wi includes a set of RSA analysis tools designed for educational cryptography, CTF challenges, and weak-key analysis. These tools help users explore common RSA failure cases, including weak factorization, known prime recovery, small exponent weaknesses, and small private exponent attacks.

The RSA toolset includes:

* RSA-FACTOR
* RSA-RHO
* RSA-ECM
* RSA-WIENER
* RSA-SMALL-E
* RSA-KNOWNPQ
* RSA-CHECKPQ
* RSA-DFROMPQ
* RSA-MINI

These tools are intended for authorized analysis, coursework, lab environments, and challenge data. They are not designed to break properly generated production RSA keys.

## RSA Challenge File Format

Most RSA modules use a text file containing RSA parameters.

Typical fields include:

```text
N = 3233
e = 17
c = 855

# Chapter 9: RSA Analysis Tools

## Overview

K1Wi includes a set of RSA analysis tools designed for educational cryptography, CTF challenges, and weak-key analysis. These tools help users explore common RSA failure cases, including weak factorization, known prime recovery, small exponent weaknesses, and small private exponent attacks.

The RSA toolset includes:

* RSA-FACTOR
* RSA-RHO
* RSA-ECM
* RSA-WIENER
* RSA-SMALL-E
* RSA-KNOWNPQ
* RSA-CHECKPQ
* RSA-DFROMPQ
* RSA-MINI

These tools are intended for authorized analysis, coursework, lab environments, and challenge data. They are not designed to break properly generated production RSA keys.

## RSA Challenge File Format

Most RSA modules use a text file containing RSA parameters.

Typical fields include:

```text
N = 3233
e = 17
c = 855

Where:

N is the RSA modulus
e is the public exponent
c is the ciphertext

Some modules require additional values such as p, q, or d, depending on the workflow.

RSA-FACTOR

RSA-FACTOR attempts Fermat/classical factorization against an RSA modulus.

Usage
./bin/k1wi RSA-FACTOR <rsa_file>
Example
./bin/k1wi RSA-FACTOR testdata/rsa/rsa_61_53_e17.txt
Example Output
RSA Input
---------
N = 3233
e = 17
c = 855

[*] RSA-Factor: starting Fermat factorization
[+] p = 53
[+] q = 61

Key Recovery
------------
d = 2753

Plaintext Recovery
------------------
m = 123

Hex plaintext:
7b

Decoded ASCII:
{
RSA-RHO

RSA-RHO attempts factorization using Pollard Rho.

Usage
./bin/k1wi RSA-RHO <rsa_file>
Example
./bin/k1wi RSA-RHO testdata/rsa/rsa_61_53_e17.txt

Pollard Rho is useful for demonstrating integer factorization against weak or small RSA moduli.

RSA-ECM

RSA-ECM attempts factorization using the Elliptic Curve Method.

Usage
./bin/k1wi RSA-ECM <rsa_file>
Example
./bin/k1wi RSA-ECM testdata/rsa/rsa_ecm_small_factor.txt

ECM is useful when one RSA factor is significantly smaller than the other.

RSA-WIENER

RSA-WIENER attempts Wiener's continued-fraction attack against RSA keys with unusually small private exponents.

Usage
./bin/k1wi RSA-WIENER <rsa_file>
Example
./bin/k1wi RSA-WIENER testdata/rsa/rsa_61_53_e17.txt

If the private exponent is not small enough, the attack will fail safely.

RSA-SMALL-E

RSA-SMALL-E checks for small public exponent weaknesses.

Usage
./bin/k1wi RSA-SMALL-E <rsa_file>
Example
./bin/k1wi RSA-SMALL-E testdata/rsa/rsa_61_53_e17.txt

This attack is only applicable when RSA is used incorrectly, such as when plaintext is small, padding is missing, and plaintext^e < N.

RSA-KNOWNPQ

RSA-KNOWNPQ decrypts RSA ciphertext when the prime factors p and q are already known.

Usage
./bin/k1wi RSA-KNOWNPQ <rsa_file> <p> <q>
Example
./bin/k1wi RSA-KNOWNPQ testdata/rsa/rsa_61_53_e17.txt 61 53

This command computes phi(N), derives the private exponent d, decrypts the ciphertext, and displays the recovered plaintext.

RSA-CHECKPQ

RSA-CHECKPQ checks whether supplied p and q values are prime.

Usage
./bin/k1wi RSA-CHECKPQ <p> <q>
Example
./bin/k1wi RSA-CHECKPQ 61 53
Example Output
[*] Starting RSA-CHECKPQ...
[*] p = 61
[+] p is prime.

[*] q = 53
[+] q is prime.

[*] RSA-CHECKPQ complete.
RSA-DFROMPQ

RSA-DFROMPQ computes phi(N) and the private exponent d from known p, q, and e.

Usage
./bin/k1wi RSA-DFROMPQ <p> <q> <e>
Example
./bin/k1wi RSA-DFROMPQ 61 53 17
Example Output
[+] phi = 3120
[+] d = 2753
RSA-MINI

RSA-MINI is a small educational RSA helper for demonstration cases.

Usage
./bin/k1wi RSA-MINI <rsa_file>
Example
./bin/k1wi RSA-MINI testdata/rsa/rsa_61_53_e17.txt
Current Limitation

RSA-MINI currently supports only small-exponent demonstration cases using:

e = 3

Inputs using unsupported public exponents are rejected.

Practical Workflow

A typical RSA challenge workflow may look like this:

./bin/k1wi RSA-FACTOR testdata/rsa/rsa_61_53_e17.txt
./bin/k1wi RSA-CHECKPQ 61 53
./bin/k1wi RSA-DFROMPQ 61 53 17
./bin/k1wi RSA-KNOWNPQ testdata/rsa/rsa_61_53_e17.txt 61 53

This workflow:

Factors the modulus.
Validates the recovered primes.
Computes the private exponent.
Decrypts the ciphertext using known p and q.
Limitations

The RSA tools are designed for weak RSA examples, educational analysis, and CTF-style challenges.

They should not be expected to factor or decrypt properly generated modern RSA keys. Strong RSA keys use sufficiently large primes, secure padding, and safe parameter choices that prevent these attacks from succeeding.

Summary

The RSA toolset gives K1Wi users a practical way to explore RSA weaknesses, recover keys from vulnerable examples, validate prime factors, compute private exponents, and decrypt challenge ciphertexts. These tools are especially useful for learning public-key cryptography, practicing CTF workflows, and analyzing intentionally weak RSA artifacts.


