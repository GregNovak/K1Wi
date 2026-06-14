# K1Wi v1.1 Development Notes

## Branch Rules

* `main` is the stable public release branch.
* All v1.1 development happens on `v1.1-dev`.
* Do not commit normal development directly to `main`.
* Keep v1.0.0 stable and public.
* Tag stable releases only after a clean build and full regression pass.

## Current Stable Release

* Version: K1Wi Framework v1.0.0
* Tag: v1.0.0
* Release branch: `main`
* Development branch: `v1.1-dev`
* Regression status at release: PASS 72 / FAIL 0 / SKIP 0
* Public repository: `https://github.com/GregNovak/K1Wi`
* Public release page: `https://github.com/GregNovak/K1Wi/releases/tag/v1.0.0`

## Current v1.1 Release Candidate

* Current RC tag: `v1.1.0-rc1`
* RC branch: `v1.1-dev`
* RC commit: `b3cee9d Prepare v1.1.0-rc1 version`
* RC regression status: PASS 80 / FAIL 0 / SKIP 0
* GitHub pre-release: published
* Final v1.1.0 is not tagged yet.
* Final v1.1.0 should be tagged from `main` only after merge, clean build, and full regression pass.

## Deferred to v1.2 or Later

* LYZER `--json`
* LYZER `--quiet`
* LYZER `--save-report`
* Full TUI dashboard
* GUI wrapper
* Windows installer

## Completed v1.1 Work

* Added Linux `install.sh` and `uninstall.sh`.
* Added README install and uninstall instructions.
* Added LYZER `--summary`, `--full`, and `--verbose` modes.
* Added real LYZER summary output.
* Changed CLI `lyzer <file>` default behavior to summary mode.
* Changed interactive shell `LYZER <file>` default behavior to summary mode.
* Updated `HELP LYZER` for summary, full, and verbose modes.
* Added regression tests for LYZER aliases and default summary behavior.
* Current v1.1 regression status: PASS 80 / FAIL 0 / SKIP 0.
* Updated main menu LYZER description.
* Removed stray manual/demo artifacts from `v1.1-dev`.
* Updated README status for `v1.1.0-rc1`.
* Updated binary version to `v1.1.0-rc1`.
* Added interactive shell `ABOUT` support.
* Published `v1.1.0-rc1` GitHub pre-release.

## v1.1 Goals

* Improve LYZER output readability. **Done for LYZER.**
* Reduce overly noisy default output. **Done for LYZER.**
* Add cleaner short/summary modes for major commands. **Done for LYZER.**
* Add better command output modes for humans and scripts. **Deferred to v1.2.**
* Begin TUI design. **Deferred to v1.2.**
* Plan future GUI architecture. **Deferred to v1.2 or later.**
* Add more regression tests for edge cases.
* Continue cautious sanitizer hardening.
* Review old Opus internal names and gradually rename public-facing leftovers.
* Improve README screenshots and usage examples.
* Add Linux install/uninstall scripts for easier local installation. **Done.**

## Track 1: Core Cleanup and Stability

Goals:

* Keep `main` stable.
* Continue all new work on `v1.1-dev`.
* Add more regression tests.
* Review sanitizer behavior carefully.
* Revisit ASAN-only intermittent LYZER crashes without blocking normal development.
* Continue small, safe hardening patches.
* Avoid risky rewrites early in v1.1.

Known sanitizer state:

```text
Normal build: strong
UBSAN-only build: strong
ASAN/ASAN+UBSAN: intermittent LYZER crashes seen earlier, possibly runtime/environment-related
```

Possible tasks:

* Run baseline regression on `v1.1-dev`.
* Add edge-case tests for commands that accept file paths.
* Add tests for invalid input handling.
* Add tests for empty files.
* Add tests for missing files.
* Add tests for lowercase/uppercase command behavior.
* Review memory handling in noisy or complex tools.
* Keep patches small and easy to review.

## Track 2: LYZER Output Redesign


Current v1.1 status:

* `LYZER <file>` now defaults to summary mode in the interactive shell.
* `k1wi lyzer <file>` now defaults to summary mode from the CLI.
* `LYZER <file> --summary` runs the short report.
* `LYZER <file> --full`, `LYZER <file> --verbose`, and `LYZER <file> ALL` run full analysis.
* `HELP LYZER` documents the new behavior.
* Regression coverage protects the new default and alias behavior.


LYZER is powerful, but the output can be noisy. v1.1 should make LYZER easier to read without removing advanced detail.

Possible modes:

```text
LYZER <file> --summary 			Done
LYZER <file> --full			Done
LYZER <file> --json			Future
LYZER <file> --save-report report.txt	Future
LYZER <file> --verbose			Done
```

Possible improvements:

* Add LYZER quick summary mode.
* Add LYZER full mode.
* Add clearer severity summary.
* Reduce noisy default output.
* Move giant tables behind verbose/full flags.
* Add save-report option.
* Make embedded-signature output easier to read.
* Make string intelligence findings cleaner.
* Make entropy findings easier to understand.
* Make carved file output easier to locate.
* Separate “findings” from “raw analysis details.”

Possible default output idea:

```text
K1Wi LYZER Summary

File:
  image.jpg

Basic:
  Type        : JPEG image
  Size        : 20,794 bytes
  Entropy     : 7.6388

Findings:
  Suspicion   : HIGH
  Strings     : 3 high-value findings
  Signatures  : JPEG header found, GZIP-like signature found
  Carving     : 1 file carved

Suggested next steps:
  - Run LYZER <file> --full for full analysis
  - Run STRING --file <file> for string intelligence
  - Review carved output directory
```

Possible full output idea:

```text
LYZER <file> --full
```

Should include:

* Full entropy analysis.
* Full heatmap.
* Full embedded-signature scan.
* Full string intelligence results.
* File carving details.
* JPEG-specific analysis when applicable.
* RS/LSB/stego-related results when applicable.

Possible JSON output idea:

```text
LYZER <file> --json
```

Purpose:

* Easier scripting.
* Future GUI/TUI integration.
* Cleaner report generation.
* Easier automated regression testing.

## Track 3: Better Command Modes

Goal:

* Make every major command easier to use from both humans and scripts.

Possible global command flags:

```text
--summary
--quiet
--verbose
--json
--output <file>
--no-color
```

Important commands to review:

```text
STRING
LYZER
EXTRACT
ENTROPY
ELFINFO
PIECALC
PIETIME
MAGIC
SEARCH
MD5
SHA256
RSA-* tools
```

Possible output-mode behavior:

```text
--summary
  Short human-readable summary.

--quiet
  Minimal output. Useful for scripts.

--verbose
  Detailed output.

--json
  Structured machine-readable output.

--output <file>
  Save command output to a file.

--no-color
  Disable ANSI color output if color is added later.
```

Possible command consistency goals:

* Similar flags should behave the same across commands.
* Error messages should be clear.
* Usage messages should be consistent.
* Help pages should show examples.
* Script-friendly modes should avoid decorative banners unless requested.
* Human-friendly modes can keep banners and section headers.

## Track 4: TUI Design

Preferred v1.1 direction:

```text
Phase 1: Improve existing terminal UI.
Phase 2: Build a ncurses-based K1Wi dashboard.
Phase 3: Later consider GUI wrapper.
```

Possible TUI main dashboard:

```text
K1Wi Main Dashboard

[1] File Tools
[2] Forensics / LYZER
[3] Extraction
[4] Hashing
[5] RSA Tools
[6] PIE / ELF Tools
[7] Cryptanalysis
[8] Settings / Help
[9] Recent Results
[0] Exit
```

Possible LYZER TUI menu:

```text
LYZER Analysis Menu

[1] Quick scan
[2] Full scan
[3] Entropy heatmap
[4] Embedded signatures
[5] String intelligence
[6] File carving
[7] JPEG analysis
[8] Save report
[0] Back
```

Possible RSA TUI menu:

```text
RSA Tools Menu

[1] RSA-FACTOR
[2] RSA-RHO
[3] RSA-ECM
[4] RSA-WIENER
[5] RSA-SMALL-E
[6] RSA-KNOWNPQ
[7] RSA-CHECKPQ
[8] RSA-DFROMPQ
[9] RSA-MINI
[0] Back
```

Possible hashing menu:

```text
Hashing Menu

[1] MD5 file hash
[2] MD5 verify
[3] MD5 compare
[4] SHA256 file hash
[5] SHA256 verify
[6] SHA256 compare
[0] Back
```

Possible TUI design goals:

* Keyboard driven.
* Clear categories.
* Safe defaults.
* Easy back navigation.
* Good help screen.
* Save reports from menu.
* No destructive action without confirmation.
* Avoid hiding the CLI; show the equivalent command when helpful.
* Keep TUI as a wrapper around the core command engine when possible.

Possible TUI safety rules:

* Do not delete files without confirmation.
* Do not overwrite reports without confirmation.
* Show output directory after extraction/carving.
* Show clear error messages when files are missing.
* Keep all dangerous or destructive actions obvious.

## Track 5: Future GUI Design

GUI should come later, after output/report structures are cleaner.

Possible future GUI direction:

* Keep core engine CLI-first.
* Add structured report output.
* Build GUI as a wrapper later.
* Avoid tying core tools directly to GUI code.
* Use `--json` or report files as the bridge between core tools and GUI.
* Keep K1Wi useful without a GUI.

Possible GUI stack options to research later:

```text
Qt
GTK
Web-based local dashboard
Python wrapper
Rust/Tauri wrapper
```

Possible GUI design goals:

* File picker for analysis.
* Dashboard for recent reports.
* LYZER report viewer.
* Searchable findings.
* Export report button.
* Safe defaults.
* Clear responsible-use reminder.
* No feature should require GUI-only logic.

For v1.1, focus on TUI and structured output first.

## Track 6: Installer / Packaging

Current v1.1 status:

* `install.sh` added.
* `uninstall.sh` added.
* README install/uninstall documentation added.
* Installer installs `k1wi` to `/usr/local/bin/k1wi`.
* Installer installs docs to `/usr/local/share/doc/k1wi`.
* Uninstaller removes installed binary and docs without touching the source tree.


Goal:

* Make K1Wi easier to install and remove.
* Keep source builds available.
* Avoid overcomplicating packaging before the tool is stable on more platforms.

Important distinction:

```text
Linux installer = good v1.1 goal
Windows install.exe = future goal unless Windows support becomes official
```

Possible v1.1 installer work:

* Add `install.sh`.			**Done.**
* Add `uninstall.sh`.			**Done.**
* Improve `make install`.
* Improve `make uninstall`.
* Install the binary as `/usr/local/bin/k1wi`.	**Done.**
* Install docs to `/usr/local/share/doc/k1wi`.	**Done.**
* Add clear install instructions to README.	**Done.**
* Add uninstall instructions to README.		**Done.**
* Add regression test to confirm `k1wi version` works after install.
* Make installer check for missing dependencies.
* Make installer fail safely if build fails.	**Done.**
* Make installer avoid deleting user files.	**Done.**
* Make installer print the installed version.	**Done.**

Possible install command:

```bash
./install.sh
```

Possible install behavior:

```text
1. Check dependencies.
2. Run make clean.
3. Run make.
4. Install ./bin/k1wi to /usr/local/bin/k1wi.
5. Install README.md, LICENSE, and DISCLAIMER.md to /usr/local/share/doc/k1wi.
6. Print install success message.
7. Print: Run with: k1wi
```

Possible uninstall command:

```bash
./uninstall.sh
```

Possible uninstall behavior:

```text
1. Remove /usr/local/bin/k1wi.
2. Remove /usr/local/share/doc/k1wi.
3. Leave user project files untouched.
4. Print uninstall success message.
```

Possible future packaging:

```text
.deb package for Ubuntu/Debian
AppImage
GitHub release binary assets
Windows .exe installer if Windows support is added
```

Installer safety goals:

* No destructive cleanup outside K1Wi install paths.
* Do not remove source tree.
* Do not remove user-created reports.
* Use clear prompts if elevated privileges are needed.
* Keep install/uninstall scripts readable and simple.
* Prefer standard Linux paths.

Possible README install section:

```text
Build from source:

  make clean
  make
  ./bin/k1wi

Install locally:

  ./install.sh
  k1wi

Uninstall:

  ./uninstall.sh
```

## Remaining v1.1 Work Candidates

Suggested order from current state:

1. Keep v1.1 changes small and release-focused.
2. Perform final README/help/menu audit.
3. Run clean build and full regression before final v1.1.0.
4. Fresh-clone or source-ZIP test final v1.1.0 before tagging.
5. Merge `v1.1-dev` into `main` only when ready for final release.
6. Tag final `v1.1.0` from `main`.

Suggested startup commands:

```bash
cd ~/Desktop/software

git status
git branch
git log --oneline --decorate -8
```

Switch to development branch:

```bash
git checkout v1.1-dev
git status
```

If needed, update from GitHub:

```bash
git pull
```

If `v1.1-dev` needs to include latest `main`:

```bash
git checkout v1.1-dev
git merge main
git push
```

Baseline validation:

```bash
make clean
make
./bin/k1wi version
./tests/run_regression.sh
git status
```

Commit this planning update:

```bash
git add TODO_v1.1.md
git commit -m "Expand v1.1 development planning notes"
git push
```

## v1.1 Development Rule

Work small.

Preferred pattern:

```text
Plan small task
Make small patch
Build
Run targeted test
Run regression
Commit
Push
```

Avoid:

```text
Huge rewrites
Mixing unrelated changes
Changing main directly
Breaking v1.0.0 release state
Adding GUI before output modes are ready
```

## Current Emotional Milestone

Current v1.1 progress:

```text
Installer scripts: complete
LYZER summary mode: complete
LYZER default output cleanup: complete
HELP LYZER docs: complete
Regression: 80/80 passing
Working tree: clean after latest checkpoint
```

K1Wi v1.0.0 is launched.

Final v1.0.0 state:

```text
Public repo: live
GitHub release: live
v1.0.0 tag: corrected and live
DISCLAIMER.md: included
LICENSE: included
README: updated
Regression: 72/72 passing
Working tree: clean
```

## Bottom line

Installer work is done. LYZER summary/default behavior is done. Regression is now 80 passing, not 72. v1.1.0-rc1 is published. Remaining larger work such as JSON output, quiet mode, full TUI, and GUI planning should move to v1.2 or later unless needed before final v1.1.0.

K1Wi v1.1 continues with stability, polish, cleaner output, better installation, and early TUI planning.
