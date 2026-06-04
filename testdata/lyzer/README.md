# K1Wi LYZER Test Assets

This directory contains official K1Wi Framework documentation and regression-testing assets used by the LYZER and EXTRACT modules.

## Files

### clean_image.png

Purpose:
Baseline image for normal image analysis.

Expected Results:

* Valid PNG image
* No embedded archives
* No intentionally embedded secrets
* Low forensic interest

---

### k1wi_demo.jpg

Purpose:
Demonstrates hidden text discovery and STRING Intelligence detection.

Embedded Content:

* K1WI-STEGO-DEMO-2026 marker
* Documentation metadata
* Example API key

Expected Results:

* High-Value Findings reported by STRING Intelligence
* Secret detection
* No embedded archive recovery

---

### embedded_zip.jpg

Purpose:
Demonstrates embedded archive detection and file carving.

Embedded Content:

* Appended ZIP archive
* Documentation payload files

Expected Results:

* ZIP signature detection
* File carving activity
* Recursive extraction support

---

## Documentation Usage

These files are referenced throughout the K1Wi Framework User Manual and may be used for regression testing, demonstrations, screenshots, and training exercises.

Version: K1Wi Framework v0.99 RC1
