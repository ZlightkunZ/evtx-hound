# Threat Model: EVTX Triage Toolkit

## Overview
This document outlines the threat model for the EVTX Triage Toolkit. Given that this tool is executed by security analysts (high privilege) on potentially hostile data (event logs from compromised machines), it is critical to model the trust boundaries.

## Trust Boundaries
1. **The User & Execution Environment:** Trusted. The script assumes the analyst is executing it in a secure sandbox or analysis VM.
2. **The Input File (`.evtx`):** UNTRUSTED. The log file is provided by potentially compromised endpoints.

## Analyzed Threats (STRIDE)

| Threat | Description | Mitigation Strategy | Status |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Adversary crafts fake event logs to mislead the parser. | The tool extracts raw strings; analysts must cross-verify with SIEM integrity checks. | Accepted Risk |
| **Tampering** | Adversary corrupts the `.evtx` binary structure to crash the parser. | Strict `try/except` blocks around parsing engine. `PermissionError` and `IOError` safely handled. | Mitigated |
| **Denial of Service** | "Zip-bomb" style massive log file designed to exhaust RAM (OOM). | Python generators and chunked reading (future roadmap) instead of loading entire files into memory. | Partially Mitigated |
| **Elevation of Privilege** | XML External Entity (XXE) injection or arbitrary code execution via malicious log fields. | Python's parsing libraries are used without expanding untrusted XML entities. | Mitigated |

## Security Assumptions
- The tool does NOT require `sudo`/Admin rights to run on local files. Do not run as root.
- The output JSON should be sanitized before being rendered in vulnerable web SIEM dashboards (to prevent XSS).
