# Windows Desktop Secure Secrets - Semgrep Rules

本目錄包含專為 **Windows 桌面應用程式** 設計的自動化安全檢測規則集（基於 [Semgrep](https://semgrep.dev/) 引擎）。

這些規則直接落實本專案之 **13 大核心安全原則**，專門透視排查一般通用掃描器經常忽略的「桌面原生安全盲點」。

---

## 1. 涵蓋規則一覽 (Rule Catalog)

| Rule ID | 規則識別碼 | 目標語言 | 嚴重度 | 描述與防護重點 |
|---|---|---|:---:|---|
| **SEC-001** | `windows-appdata-plaintext-storage` | Python, C#, JS/TS | `ERROR` | 偵測將 API Key、Token 或密碼直接以明文寫入 AppData 或一般磁碟。 |
| **SEC-002** | `windows-hardcoded-client-secret` | C#, Python, JS/TS | `ERROR` | 偵測在桌面 Public Client 二進位檔中寫死 OAuth Client Secret。 |
| **SEC-003** | `windows-silent-fallback-plaintext` | C# | `ERROR` | 偵測 catch 區塊中當安全儲存失敗時，悄悄改存明文的致命反模式。 |
| **SEC-004** | `windows-dpapi-localmachine` | C# | `ERROR` | 偵測個人桌面應用錯誤呼叫 `LocalMachine` 作用域（喪失跨使用者隔離）。 |
| **SEC-005** | `windows-secret-debug-logging` | C# | `WARNING` | 偵測在 Console 或 Logger 中打印完整機密變數。 |

---

## 2. 快速開始 (Quick Start)

只要系統安裝有 `semgrep`，在專案根目錄下達單一指令即可完成掃描：

```bash
# 基本終端機彩色檢測
semgrep scan --config ./rules/

# 產出給 AI Agent 自動解析的結構化 JSON 報告
semgrep scan --config ./rules/ --json -o audit-report.json
```

---

## 3. 與 AI Agent 打造「自動掃描與一鍵修復閉環」

本規則集可直接與 AI Coding Agent（如 Antigravity、Cursor、Claude Code）協同運作：

```text
[Semgrep 掃描透視] ──> 產生 audit-report.json ──> [AI Agent 讀取報告] ──> [依據 SKILL.md 一鍵修復代碼]
```

**提示詞範例**：
> 「我使用 `rules/windows-desktop-secrets.yml` 執行了專案掃描，發現了上述 Findings。請載入 `windows-desktop-secure-secrets` 技能，依據 Fail-Closed 原則與 Windows 原生防護標準，為我修復受影響的代碼並驗證。」
