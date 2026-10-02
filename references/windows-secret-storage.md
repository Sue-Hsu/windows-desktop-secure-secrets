# Windows 底層機密儲存機制原理與架構規範

本文件深入解析 Windows 作業系統提供的原生機密保護機制，包含 **Windows Data Protection API (DPAPI)** 與 **Windows Credential Manager** 的底層原理、作用域限制 (Scopes)、威脅模型與架構設計準則。

---

## 1. Windows Data Protection API (DPAPI)

### 1.1 核心原理
DPAPI 是 Windows 作業系統級別的對稱資料保護服務（位於 `Crypt32.dll`）。其核心價值在於：**應用程式無須自行管理、產生或硬編碼對稱加密金鑰**。

- **金鑰衍生鏈 (Key Derivation)**：
  DPAPI 的主金鑰 (Master Key) 是由使用者登入 Windows 時的憑證密碼雜湊值（或網域控制站的憑證）、搭配系統隨機產生的種子 (Salt) 與 PBKDF2 / SHA-512 派生而成。
- **主金鑰保存**：
  Master Key 本身經由使用者的密碼加密後，保存在 `%APPDATA%\Microsoft\Protect\{User-SID}\` 目錄中。
- **自動輪替與快取**：
  Windows LSA (Local Security Authority) 負責 Master Key 的生命週期與定期輪替，解密快取僅保留於受保護的系統核心記憶體中。

### 1.2 作用域深度比較：CurrentUser vs LocalMachine

呼叫 `CryptProtectData` 時，可透過旗標控制解密作用域：

| 評估維度 | `CurrentUser` (預設 / 推薦) | `LocalMachine` (`CRYPTPROTECT_LOCAL_MACHINE`) |
|---|---|---|
| **解密權限** | **僅限加密當下的同一個 Windows 使用者帳號** | **本機上運行的任何使用者、服務或軟體均可解密** |
| **適用場景** | 所有個人桌面應用程式（Godot、Electron、C#、Qt、Python 等） | 無使用者互動之 Windows NT Service、系統守護行程 |
| **安全評級** | **高**（有效隔離同機器上的其他使用者帳號） | **極危險**（同機器任何受限帳號均可讀取） |
| **反模式警告** | 嚴禁在未登入或 impersonate 錯誤時濫用 | **個人桌面應用程式嚴禁指定此旗標！** |

### 1.3 次要熵防護 (Secondary Entropy / Salt)

雖然 `CurrentUser` 能防止本機其他使用者解密，但若有惡意軟體在**同一使用者權限下**運行，理論上亦可調用 `CryptUnprotectData`。

為了提升抗滲透強度，DPAPI 提供了 `pOptionalEntropy` 參數（額外位元組陣列）：
- **運作機制**：加密與解密時必須傳入完全相同的 Entropy，否則 Windows 拒絕解密。
- **架構建議**：
  - 可以結合「應用程式特有特徵碼」或「使用者於該 Session 輸入之 PIN 碼」。
  - 切勿將固定且公開的字串以明文直接貼在開源專案中（應從編譯時混淆、本機獨立檔案或執行時期動態派生）。

### 1.4 DPAPI 威脅模型與限制

- **防護邊界 (In-Scope)**：
  - [x] 防止磁碟被拔除後進行離線分析 (Offline Disk Dump)。
  - [x] 防止 Windows 系統備份檔案被還原至其他電腦偷取。
  - [x] 防止同一台電腦上其他標準使用者帳號跨權限讀取。
- **不在防護範圍 (Out-of-Scope / Limitations)**：
  - [!] **同使用者權限惡意行程**：攻擊者若成功植入與使用者相同權限的木馬，木馬亦具備調用 DPAPI API 的權限。
  - [!] **LSASS 記憶體傾印**：若攻擊者取得本機 Administrator 權限，可傾印 LSASS 核心記憶體提權抽取 Master Key。
  - **結論**：對於極度機密之場景（如非對稱加密錢包私鑰），應採用 DPAPI 加密儲存並強制使用者於關鍵操作時輸入主密碼或呼叫 Windows Hello。

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
| **資料容量** | 適合小型機密（通常小於 512 Bytes，上限約 5KB） | 適合任意大小之資料流（幾 KB 至數 MB 設定檔） |
| **可見性** | 使用者可在「Windows 控制台 > 認證管理員」查看項目 | 對使用者透明，僅為磁碟上的加密二進位檔 |
| **整合便利性** | 適合單一 API Key、帳密或 OAuth Refresh Token | 適合將整個 JSON 設定檔或私鑰結構加密落地 |
| **架構模式** | `config.json` 僅記錄 `TargetName`，Secret 存於 CredMgr | 加密後的二進位 Payload 存於 `app_data/secrets.dat` |

---

## 3. 防範 Silent Fallback to Plaintext 的 Fail-Closed 架構

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

### 正確的 Fail-Closed 設計原則

1. **顯式中斷與通報**：
   拋出專屬例外（如 `SecureStorageUnavailableException`），在 UI 層明確告知使用者「Windows 安全金鑰保護不可用，已終止儲存操作」，阻止不安全的持久化。
2. **純記憶體降級模式 (Session-Only Memory)**：
   若使用者選擇繼續使用，僅將 Secret 保留於當前程式執行的 RAM 中（重啟後自動失效，使用者必須重新輸入）。**絕不允許自動將明文寫入磁碟**。
3. **驗證預先檢查 (Health Check)**：
   在應用程式啟動時，先以測試 Payload 執行一次 DPAPI Protect/Unprotect 迴路，確認 OS 介面健康後才接納使用者輸入機密。
