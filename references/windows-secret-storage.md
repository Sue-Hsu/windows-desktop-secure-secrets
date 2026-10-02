# Windows 底層機密儲存機制原理與架構規範

本文件深入解析 Windows 作業系統提供的原生機密保護機制，包含 **Windows Data Protection API (DPAPI)** 與 **Windows Credential Manager** 的底層原理、作用域限制 (Scopes)、威脅模型與架構設計準則。

---

## 1. Windows Data Protection API (DPAPI)

### 1.1 核心原理
DPAPI 是 Windows 作業系統級別的對稱資料保護服務（位於 `Crypt32.dll`）。其核心價值在於：**應用程式無須自行管理、產生或硬編碼對稱加密金鑰**。

- **受保護金鑰材質繫結 (Protection Material Binding)**：
  DPAPI 將受保護資料繫結至由 Windows 管理的使用者或電腦保護材質（DPAPI binds protected data to Windows-managed user or machine protection material）。應用程式無須亦無法直接管理底層 DPAPI Master Key。
- **金鑰生命週期委由作業系統 (OS-Managed Key Material)**：
  Windows 負責管理底層金鑰材質的保護、生命週期與快取機制（例如隨登入憑證與身分驗證環境維護）。內部密碼學派生與輪替細節屬於 Windows 實作機制，非公開 API 契約保證；應用程式應依賴 Windows 提供的標準 API 邊界，無須自行維護加密金鑰。

### 1.2 作用域深度比較：CurrentUser vs LocalMachine

呼叫 `CryptProtectData` 時，可透過旗標控制解密作用域：

| 評估維度 | `CurrentUser` (預設 / 推薦) | `LocalMachine` (`CRYPTPROTECT_LOCAL_MACHINE`) |
|---|---|---|
| **解密權限** | **僅限加密當下的同一個 Windows 使用者帳號** | **本機上運行的任何使用者、服務或軟體均可解密** |
| **適用場景** | 所有個人桌面應用程式（Godot、Electron、C#、Qt、Python 等） | 無使用者互動之 Windows NT Service、系統守護行程 |
| **安全評級** | **高**（有效隔離同機器上的其他使用者帳號） | **極危險**（同機器任何受限帳號均可讀取） |
| **反模式警告** | 嚴禁在未登入或 impersonate 錯誤時濫用 | **個人桌面應用程式嚴禁指定此旗標！** |

### 1.3 可選次要熵 (Optional Secondary Entropy) 的正確定位

呼叫 `CryptProtectData` 時提供 `pOptionalEntropy` 參數（額外位元組陣列）：
- **運作機制**：加密與解密時必須傳入完全相同的 Entropy，否則 Windows 拒絕解密。
- **正確認知與安全邊界限制**：
  - **靜態寫入 (Hardcoded) 的 Entropy 不是 Secret**：若 Entropy 寫死在程式碼中、隨二進位程式發布、或可從本地設定檔讀取，**它絕對不能視為對同一使用者權限下惡意軟體 (Same-User Malware) 的有效安全邊界**。同帳號運行的惡意行程能輕易從 Binary 或 Memory 中逆向取得該值。
  - **命名空間隔離 (Namespacing)**：靜態應用程式特有 Entropy 的主要價值在於「命名空間隔離」與「防止跨程式意外混用 (Accidental Cross-Use Resistance)」，避免同系統其他合法軟體意外讀取或解密結構不相容的 Blob。
  - **實質安全強化條件**：若要提供真正的額外安全防護，Entropy 必須來自**獨立受保護的外部來源**，例如：由使用者於操作時互動輸入的 PIN / Passphrase，或由外部硬體模組保護的獨立金鑰。

### 1.4 DPAPI 威脅模型與防護邊界

- **防護邊界 (In-Scope — 顯著降低風險)**：
  - [x] **防止離線磁碟分析 (Offline Disk Dump)**：主機被竊取或硬碟拔除後，攻擊者缺乏 Windows 帳號憑證與 DPAPI Master Key，無法直接解密。
  - [x] **防止不同使用者跨權限存取 (Cross-Account Isolation)**：本機其他標準 Windows 使用者帳號無法調用其自身金鑰解密 `CurrentUser` 的資料。
  - [x] **降低備份外洩風險 (Backup Protection)**：DPAPI 密文若被同步至雲端或外部儲存媒體，在缺乏原始本機使用者金鑰的環境下具備抗離線洩漏能力。
- **非防護範圍 (Out-of-Scope / Limitations — 非萬能邊界)**：
  - [!] **同使用者權限惡意行程**：攻擊者若以相同 Windows 使用者權限執行惡意代碼，惡意行程亦能呼叫 `CryptUnprotectData`。
  - [!] **管理員權限提權 (Elevation of Privilege)**：若攻擊者取得本機 Administrator / SYSTEM 權限，可傾印 LSASS 核心記憶體提權抽取 Master Key。
  - [!] **系統帳號受損**：若 Windows 帳號或機器恢復金鑰被入侵，DPAPI 保護將隨之失效。

---

## 2. Windows Credential Manager (認證管理員)

### 2.1 核心原理與架構
Windows Credential Manager 是 Windows 提供專門管理使用者憑證（如網路共用、Windows 認證、Web 登入）的安全保存庫 (Vault)。

- **資料結構**：
  每筆憑證由以下關鍵欄位組成：
  - `TargetName`：憑證的唯一識別鍵（命名建議：`<公司/專案名>:<服務名>:<帳號名>`，例如 `MyDesktopApp:OpenAI:User123`）。
  - `UserName`：使用者名稱或 Key ID。
  - `CredentialBlob`：真正的機密資料（密碼、Token、API Key 的二進位或 UTF-8 字串）。
  - `Persist`：持久化類型（`CRED_PERSIST_SESSION`、`CRED_PERSIST_LOCAL_MACHINE`、`CRED_PERSIST_ENTERPRISE`）。
- **容量上限規範 (CRED_MAX_CREDENTIAL_BLOB_SIZE)**：
  - Windows SDK 定義其二進位上限為 `CRED_MAX_CREDENTIAL_BLOB_SIZE = 5 * 512 bytes = 2560 bytes`（**約 2.5 KB**，切勿誤記為 5 KB）。
  - **適用性**：極度適合小型 Credentials、API Key、一般長度之密碼或 Refresh Token。
  - **Python keyring UTF-16 編碼特性**：在 Python 生態中，`keyring` 模組的 Windows 後端（`keyring.backends.Windows.WinVaultKeyring`）會以 UTF-16 編碼儲存字串。因 UTF-16 每個字元通常佔 2 個位元組，若字串長度換算 UTF-16 超過 2560 位元組（或超過 2560 個寬字元），寫入將會引發 `KeyringError`。程式應在儲存前主動檢核長度（`len(secret.encode('utf-16-le')) <= 2560`）。
  - **溢位風險防範**：若 Token Payload 包含豐富 Claims 或大型 SAML / OIDC 封裝而超過上限，寫入將會失敗。此時應改用 DPAPI 加密檔案 (DPAPI-protected file) 作為持久化載體。
- **呼叫底層 API**：
  Win32 函式庫 `Advapi32.dll` 提供：
  - `CredWriteW`：寫入或更新憑證
  - `CredReadW`：讀取憑證
  - `CredDeleteW`：刪除憑證
  - `CredEnumerateW`：列出憑證

### 2.2 與 DPAPI 的決策對照表

| 比較項目 | Windows Credential Manager | Windows DPAPI |
|---|---|---|
| **主要定位** | 帳號/密碼/Token 認證項 | 任意二進位資料或檔案級對稱加密 |
| **資料容量** | 適合小型機密（**上限為 2560 Bytes ≈ 2.5 KB**） | 適合任意大小之資料流（幾 KB 至數 MB 設定檔） |
| **可見性** | 使用者可在「Windows 控制台 > 認證管理員」查看項目 | 對使用者透明，僅為磁碟上的加密二進位檔 |
| **整合便利性** | 適合單一 API Key、帳密或一般長度 OAuth Refresh Token | 適合將整個 JSON 設定檔或私鑰結構加密落地 |
| **架構模式** | `config.json` 僅記錄 `TargetName`，Secret 存於 CredMgr | 加密後的二進位 Payload 存於 `app_data/secrets.dat` |
| **超額處理** | 若 Payload > 2.5 KB 寫入失敗，需改用 DPAPI 檔案儲存 | 天然支援任意長度 Payload |

### 2.3 Windows Credential Manager 威脅模型與防護邊界

- **防護邊界 (In-Scope — 顯著降低風險)**：
  - [x] **防止離線磁碟提取 (Offline Extraction)**：磁碟被拔除或系統未登入時，憑證庫受到作業系統保護，無法直接離線提取明文。
  - [x] **防止跨帳號存取 (Cross-User Isolation)**：不同 Windows 使用者帳號彼此隔離，無法相互讀取其專屬之 Credential Manager 項目。
- **非防護範圍 (Out-of-Scope / Limitations — 非萬能邊界)**：
  - [!] **同使用者權限惡意行程 (Same-User Malware)**：任何以相同 Windows 使用者帳號身分運行的程式（包括惡意軟體或未受限腳本），均可呼叫 Win32 API `CredReadW` 或 `CredEnumerateW` 讀取該使用者保存的所有憑證。
  - [!] **缺乏程式識別驗證 (No Application Identity Enforcement)**：Windows Credential Manager 本身並不驗證「呼叫者二進位檔簽名或身分」，因此無法防範同使用者權限下的程式偽冒呼叫。
  - [!] **結論**：不能將 Credential Manager 視為抵禦同一使用者惡意軟體的絕對防禦邊界。

---

## 3. 長期使用之密碼學私鑰 (Cryptographic Private Keys) 專用儲存策略

對於長期持有的密碼學非對稱私鑰（如 X.509 憑證私鑰、裝置端身分金鑰、TLS 互認證私鑰），不應一律與一般帳號密碼/Token 混用單純的 Credential Manager 或通用 DPAPI Blob。

應根據其使用場景與安全威脅模型評估專用防護策略：

1. **Windows Certificate Store (`CurrentUser\My`)**：
   - 適合標準 X.509 憑證私鑰。
   - 可在匯入時指定金鑰標記為 **Non-Exportable**，防止軟體直接導出私鑰二進位。
2. **CNG / NCrypt (Cryptography Next Generation)**：
   - 現代 Windows 密碼學核心，支援依用途分離金鑰容器（Key Container）。
   - 提供 `Microsoft Software Key Storage Provider` 進行軟體層隔離。
3. **TPM-Backed 硬體隔離儲存 (Platform Crypto Provider)**：
   - 若硬體具備 TPM 2.0 晶片，CNG 可使用硬體保護金鑰（如指定 `Microsoft Platform Crypto Provider`）。TPM-backed keys 可以將原始私鑰材質保持為不可匯出 (non-exportable)，密碼學運算均於硬體保護模組內完成，顯著降低直接抽取私鑰材質的風險（substantially reducing key-extraction risk）。
   - **威脅模型與邊界**：硬體防護不等於免於應用程式層級的侵害（does not equal application-level compromise immunity）。若惡意軟體在已獲授權的使用者情境 (authorized user context) 下運行，惡意行程仍可能嘗試調用允許的 provider API 來濫用簽章或解密操作。
4. **DPAPI-Protected Key File**：
   - 當無硬體模組或憑證庫需求時，可將加密後的私鑰檔案透過 DPAPI `CurrentUser` 加密保存，並強制在解密時結合使用者輸入的 Passphrase 作為 secondary entropy。

---

## 4. 防範 Silent Fallback to Plaintext 的 Fail-Closed 架構

許多桌面應用程式在呼叫 DPAPI 或 Credential Manager 遭遇例外（如系統權限異常、RPC 伺服器無法使用、或防毒軟體攔截）時，常出現以下**致命反模式**：

```csharp
// 致命反模式：Silent Fallback to Plaintext
try {
    SaveWithDPAPI(secret);
} catch {
    // 悄悄退回明文！重大漏洞！
    File.WriteAllText("config.json", secret);
}
```

### 4.1 正確的 Fail-Closed 設計原則

1. **顯式中斷與通報**：
   拋出專屬例外（如 `SecureStorageUnavailableException`），在 UI 層明確告知使用者「Windows 安全金鑰保護不可用，已終止儲存操作」，阻止不安全的持久化。
2. **純記憶體降級模式 (Session-Only Memory)**：
   若使用者選擇繼續使用，僅將 Secret 保留於當前程式執行的 RAM 中（重啟後自動失效，使用者必須重新輸入）。**絕不允許自動將明文寫入磁碟**。
3. **驗證預先檢查 (Health Check)**：
   在應用程式啟動時，先以測試 Payload 執行一次 DPAPI Protect/Unprotect 迴路，確認 OS 介面健康後才接納使用者輸入機密。

### 4.2 DPAPI 與 Credential Manager 解密失敗處置流程 (Recovery Flow)

在桌面環境中，解密失敗並不一定代表系統遭受攻擊，常源於正常系統狀態變化：
- **觸發情境**：
  1. **密碼重設**：使用者密碼被網域/本機管理員直接重設（非由使用者於登入畫面輸入舊密碼修改），導致 DPAPI Master Key 無法以新密碼自動解鎖。
  2. **環境轉移**：使用者更換主機、漫遊設定檔（Roaming Profile）複製失敗、或將加密檔案直接拷貝至新設備。
  3. **資料損毀**：儲存檔案不完整、磁區損壞或被第三方工具修改。

- **標準處置步驟 (Standard Recovery Flow)**：
  1. **精準區分「初次啟動」與「解密失敗」**：
     - 若憑證檔案不存在（`FileNotFoundException` / `ENOENT`），視為初次未登入狀態，直接返回 `null`。
     - 若檔案存在但解密拋出例外（`CryptographicException` / `KeyringError`），必須判定為**憑證失效（Invalidated Credential）**。
  2. **堅守 Fail-Closed 原則**：
     - 絕不可因為解密失敗就默默退回明文備份或嘗試寫入不安全的非加密檔案。
  3. **引導重新驗證 (Re-Authentication Prompt)**：
     - 攔截解密例外，向使用者友善提示：「本地安全認證已過期或失效，請重新登入」。
  4. **清理無效/損毀憑證**：
     - 主動呼叫刪除函式（`File.Delete` 或 `CredDeleteW`）清除無法解密的過期密文檔或損毀項目，避免重複觸發錯誤。
  5. **重新保護與寫入**：
     - 於使用者重新驗證成功後，取得新 Token/Password，重新調用 DPAPI / Credential Manager 進行加密寫入。

