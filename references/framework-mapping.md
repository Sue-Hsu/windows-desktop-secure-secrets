# 跨技術棧 Windows 安全儲存實作對照指引 (Framework Mapping)

本文件針對主流 Windows 桌面開發技術棧，整理 Windows 原生機密保護機制（DPAPI 與 Windows Credential Manager）的實作方式與範例代碼，協助 Agent 針對不同專案給出精準且框架正確 (Framework-Correct) 的修復代碼。

---

## 1. C# / .NET (WPF, WinForms, WinUI 3, Avalonia, .NET MAUI)

.NET 內建成熟的 DPAPI 封裝，位於 `System.Security.Cryptography`。

### 1.1 DPAPI 實作範例
```csharp
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public static class WindowsSecureStorage
{
    // 嚴格使用 CurrentUser scope；可選傳入 secondary entropy 作為命名空間隔離
    // 注意：靜態寫入的 Entropy 並非 Secret，無法抵禦同使用者權限下的惡意行程。
    // 若需實質額外防護，應傳入使用者輸入的 PIN/Passphrase 或直接傳入 null 使用標準 DPAPI。
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("AppSpecific-Secondary-Entropy-Salt");

    public static void SaveSecret(string filePath, string secret)
    {
        if (string.IsNullOrEmpty(secret)) throw new ArgumentNullException(nameof(secret));
        
        byte[] plaintextBytes = Encoding.UTF8.GetBytes(secret);
        
        // 呼叫 DPAPI 加密
        byte[] encryptedBytes = ProtectedData.Protect(
            plaintextBytes, 
            Entropy, 
            DataProtectionScope.CurrentUser
        );

        // 寫入二進位檔案，絕不落地明文
        File.WriteAllBytes(filePath, encryptedBytes);
        
        // 清理記憶體暫存 (注意：僅清理 byte[]，若外層已建立 immutable string 仍會留存於 Managed Heap)
        Array.Clear(plaintextBytes, 0, plaintextBytes.Length);
    }

    public static string ReadSecret(string filePath)
    {
        if (!File.Exists(filePath)) return null;

        byte[] encryptedBytes = File.ReadAllBytes(filePath);
        
        try
        {
            byte[] decryptedBytes = ProtectedData.Unprotect(
                encryptedBytes, 
                Entropy, 
                DataProtectionScope.CurrentUser
            );

            // 轉換為 string 供業務消費；若架構允許，應盡量以 byte[] 直接消費以利及時清整
            string secret = Encoding.UTF8.GetString(decryptedBytes);
            Array.Clear(decryptedBytes, 0, decryptedBytes.Length);
            return secret;
        }
        catch (CryptographicException ex)
        {
            // Fail-Closed: 嚴禁退回讀取未加密檔案
            throw new InvalidOperationException("無法解密憑證：Windows 帳號不符或金鑰已損毀。", ex);
        }
    }
}
```

### 1.2 Windows Credential Manager (.NET / WinRT)
在 WinUI 3 或支援 WinRT 的專案中，可直接使用 `Windows.Security.Credentials.PasswordVault`：
```csharp
var vault = new Windows.Security.Credentials.PasswordVault();
// 儲存（注意：受限於 CRED_MAX_CREDENTIAL_BLOB_SIZE ≈ 2.5 KB，過長 Token 需改用 DPAPI 檔案）
vault.Add(new Windows.Security.Credentials.PasswordCredential("MyApp:OpenAI", "UserAccount", apiKey));
// 讀取
var cred = vault.Retrieve("MyApp:OpenAI", "UserAccount");
cred.RetrievePassword();
string key = cred.Password;
```

### 1.3 密碼學私鑰專用儲存建議 (.NET)
若機密資料為**長期使用的非對稱加密私鑰**（如 X.509 憑證私鑰、數位簽章金鑰）：
- 優先使用 **Windows Certificate Store** (`X509Store`)，並設定私鑰為不可導出 (`CngKeyCreationOptions.OverwriteExistingKey`)。
- 或透過 **CNG / `CngKey`** 指定 `Microsoft Platform Crypto Provider` 儲存於 **TPM 硬體晶片**。可將原始私鑰保持為不可匯出 (non-exportable) 且在硬體內完成運算，顯著降低私鑰抽取風險（但需注意同使用者已授權情境下仍可能被惡意行程調用簽章 API）。

---

## 2. C / C++ (Win32, MFC, WinUI, Game Engines)

直接呼叫 Windows SDK 提供的原生 Win32 API。

### 2.1 DPAPI (Crypt32.lib)
```cpp
#include <windows.h>
#include <wincrypt.h>
#include <vector>
#include <iostream>

#pragma comment(lib, "Crypt32.lib")

bool ProtectDataToFile(const std::string& secret, const std::wstring& filePath) {
    DATA_BLOB DataIn;
    DATA_BLOB DataOut;

    DataIn.pbData = (BYTE*)secret.data();
    DataIn.cbData = (DWORD)secret.size();

    // 預設為 CurrentUser；若傳入 CRYPTPROTECT_LOCAL_MACHINE 則會降級為全機共享
    if (CryptProtectData(&DataIn, L"SecretData", NULL, NULL, NULL, 0, &DataOut)) {
        HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD bytesWritten;
            WriteFile(hFile, DataOut.pbData, DataOut.cbData, &bytesWritten, NULL);
            CloseHandle(hFile);
            LocalFree(DataOut.pbData);
            return true;
        }
        LocalFree(DataOut.pbData);
    }
    return false; // Fail-Closed
}
```

### 2.2 Windows Credential Manager (Advapi32.lib)
```cpp
#include <windows.h>
#include <wincred.h>

#pragma comment(lib, "Advapi32.lib")

bool WriteCredential(const wchar_t* targetName, const wchar_t* userName, const std::string& secret) {
    CREDENTIALW cred = { 0 };
    cred.Type = CRED_TYPE_GENERIC;
    cred.TargetName = (LPWSTR)targetName;
    cred.CredentialBlobSize = (DWORD)secret.size();
    cred.CredentialBlob = (LPBYTE)secret.data();
    cred.Persist = CRED_PERSIST_LOCAL_MACHINE; // 永久保存於該 Windows 使用者 Vault
    cred.UserName = (LPWSTR)userName;

    return CredWriteW(&cred, 0) != FALSE;
}
```

### 2.3 密碼學私鑰專用儲存建議 (C/C++)
若管理的是非對稱密碼學私鑰（如 RSA / ECC 私鑰）：
- 優先使用 **CNG (Cryptography Next Generation)** 之 `NCryptOpenStorageProvider`。
- 開發時可指定 `MS_PLATFORM_CRYPTO_PROVIDER` 以利用主機 **TPM (Trusted Platform Module)** 晶片。原始私鑰材質維持不可導出 (non-exportable) 且運算在硬體晶片內進行，大幅降低直接抽取私鑰材質的風險（但無法單靠硬體防止同使用者已授權情境下的惡意 API 呼叫）。
- 一般軟體金鑰則可存於 Windows Certificate Store (`CertOpenStore`) 並設為不可匯出。

---

## 3. Python Desktop (PyQt, PySide, Tkinter, wxPython)

### 3.1 推薦：`keyring` 套件 (Windows Credential Manager 後端)
在 Windows 環境下，`keyring` 預設直接對接 Windows Credential Manager：
```python
import keyring

SERVICE_NAME = "MyDesktopApp"
KEY_NAME = "openai_api_key"

def save_api_key(api_key: str):
    # 存入 Windows 憑證管理員
    keyring.set_password(SERVICE_NAME, KEY_NAME, api_key)

def load_api_key() -> str | None:
    # 自 Windows 憑證管理員取出
    return keyring.get_password(SERVICE_NAME, KEY_NAME)

def delete_api_key():
    try:
        keyring.delete_password(SERVICE_NAME, KEY_NAME)
    except keyring.errors.PasswordDeleteError:
        pass
```

### 3.2 備選：透過 `ctypes` 調用 DPAPI
無須安裝額外 C-extension，使用標準函式庫 `ctypes`：
```python
import ctypes
from ctypes import wintypes

crypt32 = ctypes.windll.crypt32

class DATA_BLOB(ctypes.Structure):
    _fields_ = [('cbData', wintypes.DWORD), ('pbData', ctypes.POINTER(ctypes.c_byte))]

def dpapi_protect(data: bytes) -> bytes:
    # 呼叫 CryptProtectData 實作 CurrentUser 加密
    # ... (透過 ctypes 包裝 DATA_BLOB)
    pass
```

---

## 4. Godot Engine (GDScript & C#)

### 核心架構警示
- **常見錯誤**：直接使用 `FileAccess.open("user://settings.cfg", FileAccess.WRITE)` 寫入 API Key 或密碼。
- **真相**：`user://` 在 Windows 上映射為 `%APPDATA%\Godot\app_userdata\<專案名>\`，**不會因為其所在位置而自動具備機密保護**；若未經 DPAPI 加密，直接寫入的檔案即為明文！

### 4.1 Godot C# 解決方案
在 Godot .NET 專案中，直接引用 `System.Security.Cryptography.ProtectedData`，將檔案二進位加密後寫入 `user://secret.bin`。

### 4.2 Godot GDScript 解決方案
1. **GDExtension**：撰寫輕量 C++ GDExtension 外掛，封裝 Win32 `CryptProtectData` / `CryptUnprotectData` 供 GDScript 呼叫。
2. **Fail-Closed 備援**：若未編譯 GDExtension，**禁止改存明文**！應改為在遊戲/工具執行期間僅存於記憶體變數 (`Global.runtime_secret`)，並在啟動時向使用者請求輸入。

---

## 5. Tauri (Rust + Frontend)

### 5.1 架構邊界規範
- **前端 (Web / JS)**：嚴禁在 `localStorage` 或前端檔案系統中存放未加密機密。
- **後端 (Rust Main Process)**：透過 Tauri Commands 代理所有機密存取。
- **OS-backed vs 應用層 Vault 區分**：
  - **Windows OS-backed 原生儲存（推薦）**：在 Rust 後端使用 `keyring` crate（對接 Windows Credential Manager）或直接透過 Win32 FFI 呼叫 Windows DPAPI (`crypt32-sys`)。
  - **`tauri-plugin-stronghold`（應用層 Encrypted Vault）**：基於 IOTA Stronghold 的軟體級保險庫（使用 Argon2 與密碼衍生金鑰）。**請注意它並非 Windows OS-backed 儲存**，若專案採用此外掛，應清楚認知其屬於 application-level encrypted vault，且需妥善管理解鎖 Snapshot 所需之密碼。

### 5.2 Rust 實作範例 (`keyring` crate - OS-backed)
```rust
use keyring::Entry;

#[tauri::command]
fn save_secret(service: String, user: String, secret: String) -> Result<(), String> {
    let entry = Entry::new(&service, &user).map_err(|e| e.to_string())?;
    entry.set_password(&secret).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn get_secret(service: String, user: String) -> Result<String, String> {
    let entry = Entry::new(&service, &user).map_err(|e| e.to_string())?;
    entry.get_password().map_err(|e| e.to_string())
}
```

---

## 6. Electron (Node.js + Chromium)

### 6.1 原生支援：`safeStorage`
Electron 內建 `safeStorage` API，在 Windows 底層直接使用 DPAPI。官方目前推薦在新專案中採用非同步 API（`encryptStringAsync` / `decryptStringAsync`），以避免阻塞 Main Process 事件迴圈：
```javascript
const { safeStorage, app } = require('electron');
const fs = require('fs').promises;
const path = require('path');

app.whenReady().then(async () => {
    // 必須先檢查作業系統金鑰庫是否可用
    if (!(await safeStorage.isAsyncEncryptionAvailable())) {
        // Fail-Closed: 嚴禁 silent fallback to plaintext!
        throw new Error("Windows 安全加密庫不可用，無法安全保存憑證。");
    }

    const secretPath = path.join(app.getPath('userData'), 'secure_credentials.bin');

    async function saveSecret(plainSecret) {
        // 優先採用官方推薦之非同步 safeStorage API，避免阻塞 Main Process
        const encryptedBuffer = await safeStorage.encryptStringAsync(plainSecret);
        await fs.writeFile(secretPath, encryptedBuffer);
    }

    async function readSecret() {
        try {
            const encryptedBuffer = await fs.readFile(secretPath);
            const { result, shouldReEncrypt } = await safeStorage.decryptStringAsync(encryptedBuffer);
            if (shouldReEncrypt) {
                const reEncryptedBuffer = await safeStorage.encryptStringAsync(result);
                await fs.writeFile(secretPath, reEncryptedBuffer);
            }
            return result;
        } catch (err) {
            if (err.code === 'ENOENT') return null;
            throw err;
        }
    }
});
```

> [!TIP]
> **API 選用指引**：`safeStorage.encryptStringAsync` 與 `decryptStringAsync` 為現行 Electron 官方正式推薦之非同步加解密 API，可防止主程序在金鑰派生時阻塞 UI 與 IPC。同步 API (`encryptString` / `decryptString`) 可能於後續版本逐步廢棄，實作時應對照目標 Electron 版本之官方 API 文件。

---

## 7. Qt (C++ / Python)

### 7.1 QtKeychain
推薦使用開源之 `QtKeychain` 函式庫，專門為 Qt 提供跨平台金鑰儲存：
- 在 Windows 下通常使用 Windows Credential Store 作為儲存後端（具體取決於編譯配置與平台支援環境，在啟用 Windows Credential Store 支援時為預設與推薦之機制）。
- 提供非同步與同步 API：`QKeychain::WritePasswordJob` / `QKeychain::ReadPasswordJob`。

---

## 8. Java Desktop (Swing, JavaFX)

Java 虛擬機本身不提供 Windows DPAPI 原生呼叫，需透過 **JNA (Java Native Access)**：
- 引入 `net.java.dev.jna:jna-platform`。
- 直接調用 `com.sun.jna.platform.win32.Crypt32Util.cryptProtectData(bytes, entropy)`。
- 解密調用 `Crypt32Util.cryptUnprotectData(encryptedBytes, entropy)`。
- 絕不使用陽春的 Base64 或自創 AES 加密並在 Java `.class` 裡寫死 Key。
