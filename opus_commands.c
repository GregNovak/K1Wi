#include <stddef.h>
#include "opus_commands.h"
int cmd_string(int argc, char **argv);

const opus_cmd_t opus_commands[] = {

    /* ===========================
       File Tools
       =========================== */
    { "OPEN",      "File Tools", "Open File" },
    { "READ", "File Tools", "File reader with raw, safe, and structured modes" },
    { "CREATE",    "File Tools", "Create File" },
    { "COPY",      "File Tools", "File Copy (with MD5 verification)" },
    { "DEL",       "File Tools", "Secure Delete (DoD / NIST / Custom)" },
    {
      "SEARCH",
      "File Tools",
      "Pattern search (ASCII/hex, overlapping matches, flags anywhere)"
    },


    { "MD5",       "File Tools", "Compute MD5 hash of a file" },
    { "SHA256",    "File Tools", "Compute or verify SHA-256 hashes"},
    { "EXTRACT",   "File Tools", "Recursive file extraction engine" },

//    { "FORENSIC",  "File Tools", "Loopback overwrite test for secure-delete compliance" },
//    { "WIPEFS",    "File Tools", "Wipe free space on a filesystem" },
    { "CLR",       "File Tools", "Clear Screen" },
    { "EXIT",         "File Tools", "Exit K1Wi\n" },

    /* ===========================
       Analysis Tools
       =========================== */
    { "LYZER",     "Analysis Tools", "Image forensics: summary default, --full for full scan" },
    { "AUTO",      "Analysis Tools", "Input detection and parser for RSA, ECC, hashes, encodings, and encrypted data" },
    { "STRING", "Analysis Tools", "String analyzer"},



    { "ENTROPY",   "Analysis Tools", "Shannon entropy calculator" },
    { "MAGIC",     "Analysis Tools", "Magic byte detector" },
    { "FREQ",      "Analysis Tools", "Frequency Analysis" },
    { "MONO",      "Analysis Tools", "Monoalphabetic Solver (quadgram hillclimb)" },
    { "DIGRAPH",   "Analysis Tools", "Digraph & Trigraph Analysis" },
    { "SOLVE",     "Analysis Tools", "Substitution Solver (advanced)" },
    { "VIGAN",     "Analysis Tools", "Vigenere Key-Length Analyzer (IC / Friedman)" },
    { "VIGCRACK",  "Analysis Tools", "Vigenere Cipher Solver (auto)" },
    { "VIGSOLVE",  "Analysis Tools", "Vigenere Key Solver (fixed length)" },
    { "VIGREFINE", "Analysis Tools", "Vigenere Key Refiner (hillclimb)" },
    { "VIGAUTO",   "Analysis Tools", "Vigenere Auto Solver (full pipeline)" },
    { "VIGENCRYPT","Analysis Tools", "Vigenere Encrypt plaintext" },
    { "CAESAR",    "Analysis Tools", "Caesar bruteforce analyzer\n" },

    /* ===========================
       Binary Tools
       =========================== */
    { "ELFINFO",   "Binary Tools", "ELF Symbol & Section Viewer" },
    { "PIECALC",   "Binary Tools", "PIE Base Calculator (with confidence scoring)" },
    { "PIETIME",   "Binary Tools", "PIE Return-Address Time Estimator\n" },

    /* ===========================
       Designation Tools
       =========================== */
    { "DESIG",        "Designation Tools", "Extract designations (X-YYYY)" },
    { "DESIGDEC",     "Designation Tools", "Decode designations" },
    { "DESIGSOLVE",   "Designation Tools", "Generate ciphertext for SOLVE" },
    { "DESIGANALYZE", "Designation Tools", "Analyze designation cipher structure\n" },

    /* ===========================
       RSA Tools
       =========================== */
{ "RSA-FACTOR", "RSA Tools", "Fermat / classical factorization" },
{ "RSA-RHO",    "RSA Tools", "Pollard Rho Factorization" },
{ "RSA-ECM",    "RSA Tools", "Elliptic Curve Method"},
{ "RSA-MINI",   "RSA Tools", "Mini RSA Solver"},
{ "RSA-WIENER", "RSA Tools", "Wiener Attack"},
{ "RSA-SMALL-E","RSA Tools", "Small exponent attack"},
{ "RSA-ROOTS", "RSA Tools", "Exact integer / even-e root helper"},
{ "RSA-KEY",    "RSA Tools", "Decrypt with PEM private key" },
{ "RSA-KNOWNPQ","RSA Tools", "Decrypt with p and q"},
{ "RSA-CHECKPQ","RSA Tools", "Check p and q"},
{ "RSA-DFROMPQ","RSA Tools", "Compute d from p,q,e\n"},


    /* ===========================
       Utility
       =========================== */
    { "TIME",    "Utility", "Show system time and timestamp utilities" }, 
    { "HELP",    "Utility", "Show general or command-specific help" },
    { "SPLASH",  "Utility", "Display the K1Wi splash banner" },
    { "MENU",    "Utility", "Show the K1Wi main menu" },
};

const size_t opus_commands_count =
    sizeof(opus_commands) / sizeof(opus_commands[0]);




