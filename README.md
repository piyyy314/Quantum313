# 🛡️ Aegis Advanced Security Toolkit & Cyber Forensic Suite

An interactive, multi-module tactical security suite designed for static code analysis, real-time telemetry parsing, cryptographic integrity audits, and enclave trusted execution environment (TEE) simulation. Deployed as a client-side offline sandbox or backed by server-side AI processing.

[![Deploy to GitHub Pages](https://github.com/your-username/your-repo/actions/workflows/deploy.yml/badge.svg)](https://github.com/your-username/your-repo/actions/workflows/deploy.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 🚀 Architectural Core Modules

The toolkit contains 18 modular components built to simulate, evaluate, and defend complex software payloads:

1. **Z3 SMT Symbolic Solver**: Deploys symbolic variables and constraints to compute condition path satisfiability, generating counterexample inputs for division by zero, buffer overflows, and auth-bypass bugs.
2. **Hardware TEE (Intel SGX / AMD SEV)**: Simulated secure enclaves capable of remote attestation key generation, local sealing/unsealing metrics, and MRENCLAVE identity reporting.
3. **Forensic Encryptor & Decryption Validator**: Securely exports forensic audits (CSV spreadsheet or JSON schema) encrypted using custom-passphrase **AES-256 (CBC with iterative PBKDF2 parameters)**, with an on-screen decryption validator to audit structural signatures.
4. **eBPF Live Audit Sandbox**: Simulated Linux kernel ring-buffer tracer capturing anomalous file manipulation, PPID exfiltration triggers, and unauthorized syscall interception (e.g. `sys_execve` on `/etc/shadow`).
5. **YARA Rule Compiler**: Pattern-matching rule compilation compiler checking hex bytes or regex targets.
6. **AST Static Vulnerability Scanner**: Heuristically sweeps submitted source codes for SQL-injection signatures, unbounded buffers, or shell subprocess commands.
7. **Malware Signature Scanner**: Fast multi-marker scanning based on an Aho-Corasick pattern tree of common packing or shellcode headers.
8. **Entropy Visualizer**: Computes Shannon entropy byte-by-byte to visual high-randomness vectors indicative of packer code, cryptographic secrets, or compressed files.
9. **DH & HKDF Ephemeral Keygen**: Interactive Diffie-Hellman modular exponentiation key negotiation.

---

## 🛠️ Tech Stack

- **Frontend**: React (v19) SPA + Vite (v6) + TypeScript (v5)
- **Styling**: Tailwind CSS (v4) + Motion
- **Cryptography**: `crypto-js` (AES-256, Hash functions), `ethers`
- **Analytics & Graphs**: Recharts + Lucide icons
- **CI/CD Deployment**: GitHub Actions workflow (`deploy.yml`) for automated static push to **GitHub Pages**.

---

## ⚙️ Development & Build Setup

### Prerequisites
Ensure you have **Node.js (v18 or higher)** and npm installed on your system.

### Installation
Clone the repository and install all node packages:
```bash
npm install
```

### Run the Dev Environment (with Server Proxy)
To start the integrated developer proxy environment with local Express routing and live socket channels:
```bash
npm run dev
```
The server will boot on port **3000** automatically.

### Run Static Build compilation
To build the fully client-side compiled assets optimized for serverless web hosting (such as GitHub Pages):
```bash
npm run build
```
This writes the final build stream into the `./dist` folder.

---

## 🧪 Unit Testing Suite

The repository contains a Vitest unit testing suite to verify cryptographic properties of the export container, symmetric key derivation, and file formatting integrity.

### Run Tests
```bash
# Execute the testing suite
npm run test
```

### Core Cryptographic Test Scenarios Verified:
- Standard unencrypted CSV/JSON file formatting.
- Symmetric AES-256 decryption with matching passphrases.
- Prevention of corrupted payloads / invalid passphrases from unsealing forensic blocks.
- Matching header signatures on the Aegis Secure Container envelope (`-----BEGIN AEGIS...`).

---

## 🚀 GitHub Pages Automated Deployment (CI/CD)

The project includes an enterprise-grade GitHub Action workflow in `.github/workflows/deploy.yml`.

### Steps to Deploy to GitHub Pages:
1. Push this repository to your GitHub profile.
2. In your GitHub repository settings, navigate to **Settings** > **Pages**.
3. Under **Build and deployment**, ensure the Source is set to **GitHub Actions** (or deployment from branch `gh-pages` if manually configuring branch outputs).
4. On every push to your `main` or `master` branch, the GitHub Action will automatically:
   - Check out your source tree.
   - Install full workspace dependencies.
   - Run the production build.
   - Push the bundle output inside `dist` directly into your `gh-pages` branch.
5. Your application will be publicly accessible at: `https://<your-username>.github.io/<your-repo-name>/`

*Note: The `vite.config.ts` configuration utilizes a relative base path (`base: './'`), meaning the compiled site will load resources seamlessly regardless of whether it is hosted on a custom root domain or a repository subdirectory.*

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

```
   ========================================================================
   🛡️ AEGIS SECURITY ARCHITECTURE : PASSIVE DEFENSE & ENCLAVE INTEGRITY
   ========================================================================
```
