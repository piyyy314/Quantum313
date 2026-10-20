# 🛡️ AEGIS Advanced Cyber Forensic & Threat Hunting Suite

```
  █████╗ ███████╗ ██████╗ ██╗███████╗    ██╗   ██╗███╗   ███╗███╗   ███╗
 ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝    ██║   ██║████╗ ████║████╗ ████║
 ███████║█████╗  ██║  ███╗██║███████╗    ██║   ██║██╔████╔██║██╔████╔██║
 ██╔══██║██╔══╝  ██║   ██║██║╚════██║    ╚██╗ ██╔╝██║╚██╔╝██║██║╚██╔╝██║
 ██║  ╚═╝███████╗╚██████╔╝██║███████║     ╚████╔╝ ██║ ╚═╝ ██║██║ ╚═╝ ██║
 ╚═╝     ╚══════╝ ╚═════╝ ╚═╝╚══════╝      ╚═══╝  ╚═╝     ╚═╝╚═╝     ╚═╝
       Kernel Sandboxing • Enclave Attestation • Heuristic AST • Forensic Ledger
```

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.8-3178c6.svg?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![React](https://img.shields.io/badge/React-19.0-61dafb.svg?logo=react&logoColor=black)](https://react.dev/)
[![Vite](https://img.shields.io/badge/Vite-6.2-646CFF.svg?logo=vite&logoColor=white)](https://vitejs.dev/)
[![TailwindCSS](https://img.shields.io/badge/Tailwind-4.1-38bdf8.svg?logo=tailwindcss&logoColor=white)](https://tailwindcss.com/)
[![CodeQL: Zero Alerts](https://img.shields.io/badge/CodeQL-Zero_Alerts_Verified-brightgreen.svg?logo=github&logoColor=white)](https://codeql.github.com/)
[![Rate Limiting: CWE-770 Hardened](https://img.shields.io/badge/OWASP-Rate_Limited_(CWE--770)-success.svg)](https://owasp.org/)
[![Crypto: AES-256-CBC / SHA-256](https://img.shields.io/badge/Crypto-AES--256_|_SHA--256-blue.svg?logo=shield&logoColor=white)](https://csrc.nist.gov/)
[![STIX 2.1 / CEF Compliant](https://img.shields.io/badge/Threat_Intel-STIX_2.1_|_CEF_|_Syslog-orange.svg)](https://oasis-open.github.io/cti-documentation/stix/intro)
[![Local AI: Ollama Offline](https://img.shields.io/badge/Local_AI-Ollama_100%25_Offline-blueviolet.svg?logo=ollama&logoColor=white)](https://ollama.ai)
[![Unit Tests: Vitest](https://img.shields.io/badge/Tests-Vitest_Passing-brightgreen.svg?logo=vitest&logoColor=white)](https://vitest.dev)

**Enterprise-grade client-side offline security sandbox, hardware enclave simulator, and persistent forensic ledger for incident response & threat hunters.**

[Key Features](#-architectural-core-modules) • [Threat Archive & Forensics](#-threat-archive--evidence-vault) • [Hardening & Rate Limiting](#-security-hardening--codeql-remediation) • [Quickstart](#-quickstart--installation) • [License](#-license)

</div>

---

## 🌟 Overview

**Aegis** is an advanced tactical cybersecurity suite engineered for static code heuristics, real-time eBPF kernel telemetry auditing, Hardware TEE enclave simulation, and cryptographic threat intelligence preservation. 

Operating strictly under a **zero-trust, privacy-first offline architecture**, Aegis ensures that no proprietary source codes, payloads, or forensic logs leave the investigator's local workstation. The platform natively routes AI coprocessor tasks to a local **Ollama** daemon (running on `localhost:11434`), falling back to optional server-side Gemini coprocessors or offline heuristic rules engines.

---

## 🚀 Architectural Core Modules

Aegis delivers 20+ integrated defensive and offensive cyber engineering modules:

| Module | Engine / Specification | Functionality |
| :--- | :--- | :--- |
| **Durable Threat Vault** | SHA-256 Merkle Fingerprints & AES-256 | Preserves forensic incident logs with date-range filters, custom time windows, and audit records. |
| **IOC Intel Harvester** | Regex Extraction Engine with Defanger | Harvests IPv4/IPv6, FQDNs, DNN hosts, CVEs, and file hashes with one-click defanging (`hxxp`, `192[.]168...`). |
| **Multi-Format Exporter** | STIX 2.1, CEF, Syslog RFC 5424, CSV | Standardized export pipeline compatible with Splunk, Elastic, QRadar, Microsoft Sentinel, and MISP. |
| **Z3 SMT Solver** | Symbolic Execution (Bitvectors & Arrays) | Computes condition path satisfiability to discover buffer overflows, integer wraparound, and auth bypasses. |
| **Hardware TEE Enclave** | Intel SGX & AMD SEV Simulator | Generates attestation measurements (`MRENCLAVE`, `MRSIGNER`), local key sealing, and enclave quotas. |
| **eBPF Sandbox Tracer** | Kernel Ring-Buffer Tracepoints | Detects unauthorized syscalls (`sys_execve`, `sys_openat` on `/etc/shadow`), PPID exfiltration, and socket spawns. |
| **YARA Rule Compiler** | Pattern Matcher & Byte Scanner | Compiles hex byte strings and regular expressions against incoming binaries and memory dumps. |
| **AST Vulnerability Scanner**| Abstract Syntax Tree Heuristics | Scans Python/JS source code for CWE-78 (Command Injection), CWE-89 (SQLi), and CWE-502 (Deserialization). |
| **Shannon Entropy Analyzer** | Byte Frequency Distribution | Computes Shannon entropy byte-by-byte to detect packers, cryptographic blobs, and encrypted shellcode. |
| **DH & HKDF Key Exchange** | Ephemeral Modular Exponentiation | Interactive Diffie-Hellman key negotiation with HKDF-SHA256 salt and info derivation. |

---

## 🗄️ Threat Archive & Evidence Vault

The **Threat Archive Vault** provides investigators with durable local storage persistence:

- **Date-Range Filtering**:
  - Quick time presets: `1 Hour`, `24 Hours`, `7 Days`, `30 Days`, or `All Time`.
  - Custom start/end `datetime-local` calendar picker with real-time match counters.
- **MITRE ATT&CK Matrix Cross-Mapping**:
  - Categorizes records by Tactics: *Initial Access (TA0001)*, *Execution (TA0002)*, *Privilege Escalation (TA0004)*, *Defense Evasion (TA0005)*, *Credential Access (TA0006)*, *Command and Control (TA0011)*.
- **Threat Hunter Regex Mode**:
  - Toggle full regex query mode (`/pattern/flags`) to hunt specific syscalls or IP ranges.
- **Investigator Chain of Custody & Evidence Locker**:
  - Immutable audit trail recording investigator IDs, timestamps, and action descriptions.
  - Cryptographic SHA-256 evidence seal calculated across payload content and timestamp.
- **Visual Cryptographic DNA Fingerprint**:
  - 64-hexadecimal-block grid representing the SHA-256 integrity hash of `localStorage.getItem('aegis_threat_archive')`.
  - Offline tamper detection: instant alerts if local records are altered externally.

---

## 🔒 Security Hardening & CodeQL Remediation

Aegis is hardened according to OWASP guidelines:

- **CodeQL Remediation (`js/missing-rate-limiting`)**:
  - All file-system operations and wildcard SPA static routes are protected by `express-rate-limit` middleware.
  - Mitigates **CWE-770** (Allocation of Resources Without Limits), **CWE-400** (Uncontrolled Resource Consumption), and **CWE-307** (Improper Restriction of Excessive Authentication Attempts).
  - Configured with separate limits for API endpoints and static file delivery to safeguard host resources against Denial of Service (DoS) attacks.
- **Safe AI Fallback**:
  - Gracefully handles transient 503 / 429 rate limits with zero application crashes, supplying deterministic offline heuristic reports when cloud or local AI is unavailable.

---

## 💻 Tech Stack

- **Frontend Runtime**: React 19 SPA, Vite 6, TypeScript 5.8
- **Styling & Motion**: Tailwind CSS v4, Motion
- **Cryptography**: `crypto-js` (AES-256-CBC, PBKDF2, SHA-256), `ethers`
- **Visualization**: Recharts, Lucide Icons
- **Backend & Middleware**: Express 4, `express-rate-limit`, `socket.io`

---

## ⚙️ Quickstart & Installation

### 1. Prerequisites
- **Node.js**: v18.0.0 or higher
- **npm**: v9.0.0 or higher
- *(Optional for 100% Local AI)*: [Ollama](https://ollama.ai) running locally (`ollama run llama3`)

### 2. Install Dependencies
```bash
git clone https://github.com/baalbek313/aegis-security-toolkit.git
cd aegis-security-toolkit
npm install
```

### 3. Start Development Server
```bash
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) in your web browser.

### 4. Build for Production
```bash
npm run build
```
Generates production-ready static assets in `./dist` and standalone Node bundle in `./dist/server.cjs`.

### 5. Run Verification Test Suite
```bash
npm run test
```

---

## 🧪 Cryptographic Verification Test Matrix

```
 ✓ src/tests/crypto.test.ts (4 tests)
   ✓ Aegis Secure Cryptographic Handshake and Forensics Envelope Integrity
     ✓ Symmetric encryption should output a valid cipher string
     ✓ Symmetric decryption with the CORRECT passphrase should recover the original plaintext exactly
     ✓ Symmetric decryption with an INCORRECT passphrase should fail to output valid UTF-8 plaintext
     ✓ Container block envelopes should parse correctly

Test Files  1 passed (1)
     Tests  4 passed (4)
```

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

```
========================================================================
🛡️ AEGIS SECURITY ARCHITECTURE : PASSIVE DEFENSE & ENCLAVE INTEGRITY
========================================================================
```
