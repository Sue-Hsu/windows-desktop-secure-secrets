# Windows Desktop Secure Secrets
### (Windows 桌面憑證與機密安全)

> A reusable AI Agent Skill for reviewing, designing, and guiding secure handling of secrets, credentials, and tokens in Windows desktop applications.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows-0078D6.svg)](#)
[![Agent: Framework--Agnostic](https://img.shields.io/badge/Agent-Universal-brightgreen.svg)](#)

> [!WARNING]
> **Notice**: This skill was independently authored and maintained by **[Sue-Hsu](https://github.com/Sue-Hsu)** with collaborative AI assistance (initial specification assistance by **[Codex](https://github.com/openai/codex)**, core implementation and verification assistance by **Antigravity**). Please review with discretion and evaluate against your project's specific threat model.

---

## 1. Introduction

Windows desktop applications frequently need to manage sensitive data, including API keys, OAuth tokens, user passwords, refresh tokens, and private keys. 

However, common user directories such as `%APPDATA%`, framework-specific configuration folders, or virtual local storage paths are merely storage locations—**they are not security sandboxes**. Files stored in AppData or other user-data directories do not receive automatic secret protection merely because of their location; without OS-level cryptographic protection (such as DPAPI), stored files remain standard filesystem objects accessible to other applications running under the user's account.

This skill equips AI coding agents (such as Antigravity, Cursor, Claude Code, and other LLM assistants) to:
- **Discover and classify** all sensitive credentials and secrets.
- **Trace secret data flows** from input and memory to disk and network.
- **Audit local storage** to eliminate plaintext persistence and custom cryptography.
- **Enforce OS-level protections**, specifically Windows Data Protection API (DPAPI) and Windows Credential Manager.
- **Detect exposure** across debug logs, exception handlers, clipboard operations, export bundles, and backups.
- **Prevent silent fallbacks** to plaintext when secure storage APIs fail.
- **Guide rotation and revocation** when a secret has been committed or leaked.
- **Verify remediations** to ensure fail-closed security.

---

## 2. Why This Skill Exists

Desktop client security differs fundamentally from server-side security. Common vulnerability patterns frequently observed in desktop applications include:

1. **Plaintext Persistence in AppData**: Storing raw API tokens or passwords in `%APPDATA%\MyApp\config.json` or SQLite databases without encryption.
2. **False Security Boundaries**: Relying on `.gitignore` as a security boundary, failing to realize local disk files remain unencrypted.
3. **Silent Fallback to Plaintext**: Swallowing exceptions from encryption APIs and quietly writing unencrypted JSON as a backup plan.
4. **Embedded Client Secrets**: Hardcoding OAuth Client Secrets into desktop binaries, failing to recognize that desktop applications are Public Clients.
5. **Debug Log and Crash Dump Leaks**: Printing authorization headers or full tokens into application logs or crash reports.
6. **Insecure Export and Backup Features**: Offering "Export Settings" or relying on automated cloud folder syncing (e.g., OneDrive) that packages plaintext secrets.
7. **Homegrown Cryptography**: Attempting to hide secrets with Base64 encoding, XOR loops, or hardcoded AES keys.

This skill provides automated guidance to systematically identify and eradicate these patterns.

---

## 3. Secret Storage Decision Flow (Decision Tree)

Follow this decision tree to determine the appropriate storage mechanism for sensitive data:

```mermaid
flowchart TD
    Start["Data to persist locally"] --> Q1{"Would unauthorized exposure<br>lead to impersonation,<br>financial loss, or data breach?"}
    
    Q1 -- "No<br>(Theme, window layout, audio volume)" --> A1["【Standard File Storage】<br>config.json / SQLite / INI<br>No encryption required"]
    
    Q1 -- "Yes<br>(Credentials, Tokens, API Keys, Private Keys)" --> Q2{"Is this an OAuth 2.0<br>Client Secret?"}
    
    Q2 -- "Yes" --> A2["【Do Not Store on Desktop】<br>Desktop applications are Public Clients; binaries can be decompiled.<br>Adopt OAuth PKCE flow (RFC 7636)<br>or delegate exchange to a backend service (BFF)"]
    
    Q2 -- "No" --> Q3{"Is this a long-lived<br>cryptographic private key or cert?<br>(e.g. Code signing, client certificate)"}
    
    Q3 -- "Yes" --> A3["【Windows Certificate Store / CNG】<br>Store in Windows Certificate Store<br>or isolate via TPM 2.0 hardware"]
    
    Q3 -- "No<br>(Common API keys, passwords, bearer tokens)" --> Q4{"Is payload length under 2.5 KB?<br>(CRED_MAX_CREDENTIAL_BLOB_SIZE = 2560 Bytes)"}
    
    Q4 -- "Yes<br>(Username/Password, single API Key, short Token)" --> A4["【Windows Credential Manager】<br>API: CredWrite / keyring"]
    
    Q4 -- "No<br>(Lengthy OAuth token chains, composite config)" --> A5["【DPAPI-Protected File】<br>Encrypt with DPAPI CurrentUser<br>before writing ciphertext to AppData<br>API: CryptProtectData / ProtectedData"]
```

> 📖 **Reference Guide**: For storage technical specifications, common security misconceptions, fail-closed handling rules, language snippets, and scan guidance, see [`references/cheat-sheet.md`](references/cheat-sheet.md).

---

## 4. Scope

### What This Skill Covers
- Secret inventory, classification, and sensitivity tiering.
- Windows OS-level credential management:
  - **Windows Data Protection API (DPAPI)** (`CryptProtectData`, `ProtectedData`, `safeStorage`).
  - **Windows Credential Manager** (`CredWrite`, `PasswordVault`, `keyring`).
- OAuth 2.0 and OIDC for Native Apps (RFC 8252, RFC 7636 PKCE).
- Complete 11-stage credential lifecycle auditing (Input, Memory, Storage, Transmission, Usage, Logging, Error Handling, Export, Backup, Deletion, Rotation/Revocation).
- Guidance on credential rotation and Git history scrubbing.
- Framework-specific implementation mappings (.NET, C++, Python, Godot, Electron, Tauri, Qt, Java).

### What This Skill Is NOT
- **Not a Password Manager**: It does not replace enterprise credential vaults like 1Password, Bitwarden, or HashiCorp Vault.
- **Not a Full Penetration-Testing Suite**: It does not perform active runtime fuzzing or exploit payload delivery.
- **Not a General Malware Scanner**: It does not detect trojans, keyloggers, or operating-system-level rootkits.
- **Not a Cryptographic Primitive Library**: It guides the correct invocation of official Windows APIs rather than shipping novel cryptographic implementations.

---

## 5. Supported Use Cases

- **AI-Powered Desktop Applications**: Safely storing LLM provider API keys entered by end users.
- **Desktop Clients with Cloud Authentication**: Securely managing OAuth 2.0 Access and Refresh Tokens for Google, GitHub, or enterprise IdPs.
- **Developer and Database Tools**: Storing database passwords and service connection strings on local machines.
- **Desktop Games and Utilities**: Protecting player authentication tokens in Godot, Unreal, or Unity Windows exports.
- **Pre-Release Security Audits**: Running comprehensive reviews before packaging installers or distributing MSIX/exe packages.

---

## 6. How the Skill Works (7-Phase Workflow)

When this skill is triggered, the AI Agent follows a structured 7-phase audit workflow:

```mermaid
flowchart LR
    P1["Phase 1<br>Secret Inventory"] --> P2["Phase 2<br>Data Flow Trace"]
    P2 --> P3["Phase 3<br>Storage Review"]
    P3 --> P4["Phase 4<br>Exposure Review"]
    P4 --> P5["Phase 5<br>Platform Mapping"]
    P5 --> P6["Phase 6<br>Remediation"]
    P6 --> P7["Phase 7<br>Verification"]
```

1. **Phase 1 — Secret Inventory**: Identify and categorize all credentials, tokens, keys, and public client identifiers.
2. **Phase 2 — Data Flow Trace**: Follow each secret across its lifecycle (Input → Memory → Storage → Transmission → Logging → Deletion).
3. **Phase 3 — Storage Review**: Audit local disk persistence for plaintext storage, weak hashing, or improper scopes.
4. **Phase 4 — Exposure Review**: Inspect source code, Git history, exception traces, UI elements, and export utilities for leaks.
5. **Phase 5 — Platform Mapping**: Identify the application's runtime language and map to the appropriate Windows API.
6. **Phase 6 — Remediation**: Deliver concrete, framework-correct, fail-closed code rewrites and evaluate rotation needs.
7. **Phase 7 — Verification**: Verify that secure storage is active, exceptions fail safely, and logs remain sanitized.

---

## 7. Core Security Principles

1. **AppData is Storage, Not a Sandbox**: User data directories offer filesystem separation, not cryptographic defense.
2. **Never Persist Plaintext Secrets**: Any secret capable of authentication must never touch disk unencrypted.
3. **Prefer OS-Level Protection**: Delegate key management to Windows Credential Manager or DPAPI (`CurrentUser`).
4. **No Homegrown Crypto or Hardcoded Keys**: Avoid Base64, custom XOR loops, and embedded AES keys in binaries.
5. **Fail Closed (Zero Silent Fallback)**: If secure storage fails, halt or downgrade to transient session memory—never silently dump plaintext.
6. **Audit the Full Lifecycle**: Defend secrets during input, in-memory residence, network transit, logging, and deletion.
7. **UI and Log Masking**: Mask inputs by default and sanitize exception outputs and logging calls.
8. **Desktop Apps are Public Clients**: Never embed OAuth Client Secrets in desktop binaries; enforce PKCE (RFC 7636).
9. **Separate Secrets from Preferences**: Keep window sizes and themes in standard JSON; reserve DPAPI/Vaults for actual credentials.
10. **Rotate Leaked Secrets**: If a key touched Git or a log file, removing it is insufficient—it must be revoked and rotated.

---

## 8. Installation & Getting Started

Choose the approach that best fits your workflow:

### Option 1: Direct Executable Download (Recommended for Quick Scans)
If you simply want to scan and audit your Windows desktop projects, **you do NOT need to clone the entire repository or install Python**:
1. Download the standalone portable binary from **[GitHub Releases](https://github.com/Sue-Hsu/windows-desktop-secure-secrets/releases)**:
   👉 **`win-secret-scanner.exe`**
2. Double-click to run in Windows Explorer.
3. Drag-and-drop any project folder into the terminal window to run an instant scan and generate HTML/Markdown reports.

---

### Option 2: Install as an AI Agent Skill
If you want AI coding assistants (such as Antigravity, Claude Code, Cursor, or Codex) to automatically apply these Windows security rules and review secret lifecycles during development, clone the repository into your agent's skill directory:

- **Antigravity / Gemini CLI (Global)**:
  ```bash
  git clone https://github.com/Sue-Hsu/windows-desktop-secure-secrets.git ~/.gemini/config/skills/windows-desktop-secure-secrets
  ```
- **Claude Code (User / Project)**:
  ```bash
  # Project-level or tool-specific skill path
  git clone https://github.com/Sue-Hsu/windows-desktop-secure-secrets.git .claude/skills/windows-desktop-secure-secrets
  ```
- **Cursor / General Agent Workspaces**:
  ```bash
  git clone https://github.com/Sue-Hsu/windows-desktop-secure-secrets.git .agents/skills/windows-desktop-secure-secrets
  ```

---

## 9. Usage

Trigger the skill in your AI assistant by asking questions or providing audit prompts:

- *"Review this Windows desktop project for unsafe secret and credential storage."*
- *"Audit our API key and OAuth token handling using windows-desktop-secure-secrets."*
- *"Check whether our Godot / .NET / Electron app stores credentials securely."*
- *"We are preparing for release. Verify that no secrets leak into AppData, logs, or exports."*

---

## 10. Automated Static Security Scanning

To enable deterministic verification and CI/CD integration, this project provides two complementary automated scanning approaches:

### Option A: Standalone Python CLI (`win-secret-scanner`)

A zero-dependency, standalone static analysis tool built entirely on the Python standard library. It requires no third-party package installation and can run directly or be compiled into a portable `.exe`:

```bash
# Direct run with Python (zero external dependencies)
python win_secret_scanner.py path/to/your/project

# Generate structured JSON report (ideal for AI Agent closed-loop remediation)
python win_secret_scanner.py path/to/your/project --format json -o audit-report.json

# Generate GitHub Flavored Markdown report
python win_secret_scanner.py path/to/your/project --format markdown -o audit-report.md

# Set custom exit code threshold (critical, high, medium, low, none)
python win_secret_scanner.py path/to/your/project --fail-on high
```

#### Portable Binary Packaging (.exe) & Interactive Mode
You can package the scanner into a standalone green executable (`dist/win-secret-scanner.exe`) via PyInstaller:

```bash
# Install PyInstaller if not already present
pip install pyinstaller

# Run one-click build script
python scripts/build_exe.py
```
- **Interactive Double-Click Mode**: When launched directly from Windows Explorer (no CLI arguments), `win-secret-scanner.exe` automatically enters an interactive console mode—supporting folder drag-and-drop, one-click export of timestamped HTML and Markdown reports (`audit-report_yyyyMMddHHmm.html` / `.md`), and continuous scanning menu options (`[1] Continue scanning` / `[2] Exit`).
- **Automated CLI Mode**: When invoked with arguments in a terminal or CI/CD pipeline (supporting `-f html`, `-f markdown`, `-f json`), it runs non-interactively with standard exit codes.
*(Note: Binary executables are excluded from Git version control via `.gitignore` to maintain repository cleanliness).*

---

### Option B: Semgrep Ruleset (`rules/`)

For teams with existing [Semgrep](https://semgrep.dev/) pipelines, preconfigured production rules are provided in [`rules/`](rules/):

```bash
# Run automated scan across your desktop codebase
semgrep scan --config ./rules/

# Export JSON findings for automated CI/CD processing
semgrep scan --config ./rules/ --json -o audit-report.json
```

Both engines enforce consistent vulnerability rules:
- **SEC-001**: Detection of plaintext secrets persisted in AppData or user folders (Python, C#, JavaScript/TypeScript).
- **SEC-002**: Embedded OAuth Client Secrets in Public Client desktop binaries (C#, Python, JavaScript/TypeScript).
- **SEC-003**: Silent fallback to plaintext in exception handlers (C#).
- **SEC-004**: Insecure `DataProtectionScope.LocalMachine` usage (C#).
- **SEC-005**: Plaintext tokens and keys logged to Console or debug streams (C#).

---

## 11. Example Findings

All findings emitted by the skill follow an actionable format with severity, code diffs, and risk-based rotation guidance.

### Example 1: Plaintext Storage in User Directory

````markdown
### [High] SEC-001: Plaintext API Key Persisted in AppData

- **File / Location**: `src/config/storage.py:42`
- **Secret Type**: API Key (Cloud Provider)
- **Current Behavior**:
  The application writes user-provided API keys directly to `%APPDATA%\MyApp\settings.json` using raw `json.dump()`.
- **Risk**:
  Any non-elevated process or malware running under the same user account can read this file in plaintext without requiring administrator privileges.
- **Recommended Fix**:
  Use the Windows Credential Manager via the `keyring` package to isolate credentials from ordinary preferences.
- **Concrete Code Snippet**:
  ```python
  import keyring

  # Save to Windows Credential Manager
  keyring.set_password("MyDesktopApp", "cloud_api_key", api_key)
  ```
- **Platform / Framework Consideration**:
  Ensure the active backend is `WinVaultKeyring` and fail closed if unavailable.
- **Rotation Required**:
  **No** (Evaluated via Threat Model: The API key only existed on a controlled local developer disk, was never committed to Git, was never logged or backed up to cloud sync, and the host shows no indicators of compromise. However, the plaintext file must be purged and replaced with Windows Credential Manager immediately).
````

### Example 2: Committed Credentials in Repository History

````markdown
### [Critical] SEC-002: Hardcoded Production Client Secret Committed to Git

- **File / Location**: `Assets/Scripts/OAuthService.cs:14`
- **Secret Type**: OAuth Client Secret
- **Current Behavior**:
  An OAuth Client Secret is hardcoded in source code and present in past Git commit history.
- **Risk**:
  Desktop applications are Public Clients. Anyone with repository access or decompilation tools can extract this secret to impersonate the application.
- **Recommended Fix**:
  Migrate to OAuth 2.0 Authorization Code Flow with PKCE (Proof Key for Code Exchange) where no Client Secret is stored on the client.
- **Rotation Required**:
  **Yes**. Revoke the compromised secret immediately in the cloud provider console and purge repository history using `git-filter-repo`.
````

---

## 12. Framework Mapping

This skill is designed to be **framework-agnostic**. The core principles apply universally, while framework-specific implementations are detailed in [`references/framework-mapping.md`](references/framework-mapping.md):

| Framework / Language | Recommended Mechanism | Reference Guide |
|---|---|---|
| **.NET / C#** (WPF, WinUI, MAUI) | `ProtectedData` (DPAPI CurrentUser), `PasswordVault` | [`examples/dotnet-dpapi.md`](examples/dotnet-dpapi.md) |
| **Electron** (Node.js) | `safeStorage` (Main Process only) | [`examples/electron-safestorage.md`](examples/electron-safestorage.md) |
| **Python Desktop** (PyQt, Tkinter) | `keyring` (Windows Credential Manager) | [`examples/python-keyring.md`](examples/python-keyring.md) |
| **Godot Engine** (4.x / 3.x) | C# `ProtectedData` or GDExtension DPAPI | [`examples/godot-credentials.md`](examples/godot-credentials.md) |
| **C / C++** (Win32, MFC) | `CryptProtectData` (Crypt32), `CredWriteW` (Advapi32) | [`references/framework-mapping.md`](references/framework-mapping.md) |
| **Tauri** (Rust) | Native OS `keyring` crate (CredMgr) / `crypt32`; or `tauri-plugin-stronghold` (app-level vault) | [`references/framework-mapping.md`](references/framework-mapping.md) |
| **Qt** (C++ / Python) | `QtKeychain` library (Windows Credential Store) | [`references/framework-mapping.md`](references/framework-mapping.md) |
| **Java Desktop** | JNA wrapper for `Crypt32Util` | [`references/framework-mapping.md`](references/framework-mapping.md) |

---

## 13. Threat Model & Limitations

Understanding what OS-level security can and cannot do is essential:

- **At-Rest Protection**: Windows DPAPI and Credential Manager protect data *at rest* against offline attacks, disk theft, and cross-account unauthorized access.
- **Same-User Malicious Processes**: Any untrusted software executing with the same Windows user privileges can theoretically invoke `CryptUnprotectData` to decrypt DPAPI data. For highly sensitive workflows (e.g., cryptocurrency wallets), combine DPAPI with user-supplied master passwords or Windows Hello.
- **Static Review Boundaries**: Static analysis cannot fully guarantee runtime memory safety (e.g., memory dumps or process injection).
- **Third-Party Providers**: Cloud IdP policy configurations and external token validity remain outside local client control.

---

## 14. Security Notes

- **Synthetic Examples**: Never commit real API keys, tokens, or credentials to this repository. All examples must use synthetic placeholders.
- **Redaction**: Always mask secrets in audit outputs (e.g., `sk-ant-****xyz`).
- **Fail-Closed Verification**: Always test the application's behavior when Windows credential storage APIs throw exceptions.

---

## 15. Project Structure

```text
windows-desktop-secure-secrets/
├── SKILL.md                              # Main agent skill definition and instructions
├── README.md                             # English documentation and usage guide
├── README.zh-TW.md                       # Traditional Chinese documentation
├── LICENSE                               # MIT License
├── .gitignore                            # Git exclusion rules
├── win_secret_scanner.py                 # Standalone zero-dependency Python CLI scanner
├── scanner/                              # Core static analysis scanner engine
│   ├── __init__.py                       # Package exports
│   ├── models.py                         # Data models (Finding, ScanResult, Severity)
│   ├── rules.py                          # Rule implementations (SEC-001 ~ SEC-005)
│   ├── engine.py                         # Path exploration, ignore filters, batch execution
│   └── reporters.py                      # Terminal console, Markdown, and JSON reporters
├── scripts/                              # Utility build & automation scripts
│   └── build_exe.py                      # One-click PyInstaller standalone .exe build utility
├── rules/                                # Automated Semgrep rules for static code audit
│   ├── README.md                         # Rule catalog & runner guide
│   └── windows-desktop-secrets.yml       # Production Semgrep rule definitions
├── references/                           # Detailed technical reference guides
│   ├── cheat-sheet.md                    # Pragmatic decision tree & anti-pattern cheat sheet
│   ├── windows-secret-storage.md         # In-depth DPAPI & Credential Manager mechanics
│   ├── framework-mapping.md              # Cross-framework implementation guide
│   ├── oauth-desktop-security.md         # Public Clients, PKCE, and desktop OAuth
│   └── credential-lifecycle.md           # 11-stage secret lifecycle tracking
├── examples/                             # Practical implementation examples
│   ├── dotnet-dpapi.md                   # C# / .NET implementation
│   ├── electron-safestorage.md           # Electron Main process implementation
│   ├── python-keyring.md                 # Python keyring implementation
│   └── godot-credentials.md              # Godot 4.x credential management
└── evals/                                # Deterministic regression evaluation suite
    ├── README.md                         # Evaluation suite documentation & runner guide
    ├── test-cases.json                   # Structured test cases, expected verdicts & rotation criteria
    └── fixtures/                         # Miniature vulnerable and compliant code fixtures
        ├── case1_storage.py              # Case 1: Plaintext API key in AppData
        ├── case2_oauth_service.cs        # Case 2: Hardcoded Client Secret & console logging
        └── case3_secure_dpapi.cs         # Case 3: Compliant DPAPI CurrentUser & Fail-Closed
```

---

## 15. References & Inspiration

This skill was independently developed and drew conceptual inspiration from:
- [superagent-ai/skills](https://github.com/superagent-ai/skills) (specifically `crypto-secrets` for secrets hygiene and structured reporting).
- [agents-inc/skills](https://github.com/agents-inc/skills) (specifically `desktop-storage-electron` for architectural separation of preferences and credentials).

*Note: This project is independently authored and is not affiliated with or endorsed by those repositories.*

---

## 16. License

This project is licensed under the [MIT License](LICENSE).

---

## 17. Contributing

Contributions are welcome! We appreciate improvements in:
- Additional framework mappings (e.g., Flutter Desktop, Go/Fyne).
- Nuanced threat model considerations and mitigation patterns.
- Expanded automated test patterns and verification checklists.

---

## 18. Contributors & Credits

Special thanks to the primary contributors and AI coding partners:

- **[Sue-Hsu](https://github.com/Sue-Hsu)** - Project Owner & Maintainer
- **[Codex](https://github.com/openai/codex)** ([OpenAI](https://openai.com/)) - Initial specification assistance
- **Antigravity** ([Google DeepMind](https://deepmind.google/)) - Implementation assistance & verification workflows

---

## 19. Disclaimer

This skill provides automated security guidance and review assistance. It does not replace a comprehensive professional cybersecurity audit and does not guarantee that an application is completely impervious to all attack vectors.
