# Windows 桌面應用 OAuth 2.0 / OIDC 安全與 Public Client 防護指引

桌面應用程式（Native Apps）在整合現代身分驗證（如 OAuth 2.0、OpenID Connect、Google Login、Microsoft Entra ID 等）時，面臨與 Web 應用程式截然不同的安全邊界與威脅模型。

本文件旨在規範桌面應用中的 OAuth 安全架構，防範「將 Desktop Client 視為 Confidential Client」、「內嵌 Client Secret」與「未加密儲存 Refresh Token」等典型高危漏洞。

---

## 1. 桌面客戶端的本質：Public Client (RFC 8252)

依據 OAuth 2.0 (RFC 6749) 與 Native Apps 最佳實踐 (RFC 8252)：
- **Confidential Client (機密客戶端)**：運行於受控伺服器後端，能夠安全保密其憑證（如 Client Secret）。
- **Public Client (公開客戶端)**：運行於使用者裝置上的本機原生軟體（包含 Windows 桌面應用程式）。二進位檔案可被反編譯、逆向分析、記憶體傾印或透過除錯器掛鉤。

### 核心鐵律：桌面端禁止內嵌 Client Secret
- **高危反模式**：在 C#、C++、Python、Godot 或 Electron 程式碼中寫入 `CLIENT_SECRET = "GOCSPX-..."`。
- **現實威脅**：任何使用者或攻擊者只要使用字串擷取工具（如 `strings`）、反編譯器（如 dnSpy、Ghidra）或抓包工具，即可數秒內完整提取 Client Secret，進而冒用該應用程式身分發動憑證濫用與釣魚攻擊。
- **正確架構**：
  1. **原生 Public Client 模式**：在身分提供商（IdP，如 Google Cloud Console、Azure Portal）建立憑證時，類型一律選擇 **Desktop App / Native Client**。在此模式下，授權流程不強制要求 Client Secret。
  2. **BFF (Backend For Frontend) 代理模式**：若身分提供商強制要求 Client Secret，桌面應用**絕不能直接與 IdP 交換 Token**，而必須透過自建的受控後端 Web 服務作為轉送代理，由後端維護 Client Secret。

---

## 2. 授權碼流程與 PKCE (RFC 7636)

桌面原生應用程式整合 OAuth 2.0，**強制要求使用 Authorization Code Flow with PKCE (Proof Key for Code Exchange)**。

### 2.1 PKCE 運作流程
1. **產生驗證碼 (Code Verifier)**：
   客戶端產生高熵隨機字串（43-128 字元，使用密碼學安全隨機產生器，如 `RNGCryptoServiceProvider` / `crypto.randomBytes`）。
2. **計算挑戰碼 (Code Challenge)**：
   對 `Code Verifier` 執行 SHA-256 雜湊，並進行 URL-safe Base64 編碼（`code_challenge_method = S256`；**嚴禁使用 plain 模式**）。
3. **發起授權請求**：
   開啟系統預設瀏覽器（System Browser），在授權 URL 帶入 `code_challenge` 與 `code_challenge_method=S256`。
4. **回調與交換 Token**：
   瀏覽器回調帶回 `authorization_code`。桌面客戶端向 Token 端點發送 POST 請求，並隨附原始的 `code_verifier`。
5. **IdP 驗證**：
   IdP 將收到的 `code_verifier` 進行 SHA-256 運算，確認與先前的 `code_challenge` 一致，才核發 Token。

> [!IMPORTANT]
> PKCE 能有效防止攻擊者在同一本機上搶先攔截 `authorization_code`（例如透過自訂 URI Scheme 劫持），因為攻擊者沒有記憶體中的原始 `code_verifier`，無法向 IdP 換取 Token。

---

## 3. Redirect URI 與回調接收機制

桌面應用接收 OAuth 授權碼的兩種主要模式：

### 3.1 推薦模式：Loopback Interface (本機迴路伺服器)
- 桌面應用程式在啟動授權前，於本機隨機連接埠啟動暫時性 HTTP 監聽器（例如 `http://127.0.0.1:0`）。
- **優勢**：
  - 安全性最高，不易被惡意軟體偽造協議劫持。
  - 符合 RFC 8252 推薦規範。
- **安全細節**：
  - 必須驗證 `state` 參數以防範 CSRF。
  - 接收到回調後立即關閉本機 HTTP 伺服器。

### 3.2 替代模式：Custom URI Scheme (如 `myapp://auth-callback`)
- 於 Windows 註冊表建立自訂 URL Protocol。
- **安全風險 (Scheme Hijacking)**：
  - Windows 上任何具備標準使用者權限的軟體皆可修改註冊表搶佔該 Scheme。
- **防禦手段**：
  - 若使用 Custom Scheme，**絕對強制啟用 PKCE 與嚴格 `state` 隨機檢驗**。

---

## 4. Token 敏感情境與階層式安全防護

桌面應用程式從 OAuth 取得之各類憑證，應依敏感等級採取差異化防護：

| 憑證類型 | 敏感度 | 建議防護策略 | 落地規範 |
|---|---|---|---|
| **Public Client ID** | 低 (公開) | 可明文存於程式碼或一般設定 | 無需加密 |
| **State / Nonce** | 中 (短暫) | 僅於發起授權至回調期間留存記憶體 | **嚴禁持久化** |
| **Code Verifier** | 中 (一次性) | 僅於交換 Token 前留存記憶體 | **嚴禁持久化**，換取完立即銷毀 |
| **ID Token** | 中 (含使用者個資) | 僅於 Session Memory 中解析 Claims | 若需快取，必須 DPAPI 加密 |
| **Access Token** | **高** (具備資源操作權限) | 優先純記憶體保存；過期時使用 Refresh Token 換新 | 若需跨重啟保持，必須經 **DPAPI (CurrentUser)** 加密儲存 |
| **Refresh Token** | **極高 (長期最高控制權)** | **強制 OS 等級保護** | **必須存入 Windows Credential Manager 或經 DPAPI 加密，嚴禁明文寫入檔案** |

---

## 5. Token 生命週期管理與註銷 (Revocation & Sign-out)

當使用者在桌面應用中點擊「登出 (Sign Out)」或「重設帳號」時，必須執行**完整註銷協議**：
1. **呼叫 IdP 撤銷端點 (RFC 7009)**：
   向提供商發送 Revocation 請求，作廢 Access Token 與 Refresh Token。
2. **清除本機 Windows Credential / DPAPI 檔案**：
   - 呼叫 `CredDeleteW` 或 `ProtectedData` 檔案刪除。
   - 覆寫二進位檔案內容後刪除，防止磁碟殘留還原。
3. **清理記憶體**：
   將快取於變數中之 Token 字串執行覆蓋或重置為 null。
