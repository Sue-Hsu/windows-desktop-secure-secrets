# Example: Electron Main Process SafeStorage

This example shows how to use Electron's native `safeStorage` module (which calls Windows DPAPI under the hood) in the Main process, ensuring secrets are encrypted before persisting to `app.getPath('userData')`.

---

## Architecture Rule
- **Main Process Only**: All cryptographic and credential operations run in the Electron Main process.
- **No Direct Renderer Access**: Renderers communicate via secure IPC channels (`ipcMain.handle`).
- **Never Plaintext in Electron Store**: Never store unencrypted secrets in `electron-store` or plain JSON files.

---

## Implementation (`src/main/secureStorage.js`)

```javascript
const { safeStorage, app } = require('electron');
const fs = require('fs').promises;
const path = require('path');

class ElectronSecureStore {
    constructor() {
        this.storageFile = path.join(app.getPath('userData'), 'vault.bin');
    }

    /**
     * Checks whether OS-level encryption is available on the current Windows installation.
     * Handles temporary unavailability scenarios (e.g. system session initialization, locked context).
     */
    async ensureEncryptionAvailable() {
        const isAvailable = await safeStorage.isAsyncEncryptionAvailable();
        if (!isAvailable) {
            // FAIL-CLOSED: Stop immediately instead of silent plaintext fallback.
            // In cases of temporary unavailability (e.g., safeStorage.isTemporarilyUnavailable() if supported,
            // or locked session state), applications should adopt a retry/defer strategy or keep the credential
            // in volatile memory only for the current session. NEVER fall back to plaintext persistence.
            throw new Error('OS-level encryption is currently unavailable. Operation aborted to preserve security.');
        }
    }

    /**
     * Helper to write file atomically via a temporary file and rename.
     * Prevents file corruption if application crashes or power is lost mid-write.
     */
    async writeSecretFile(buffer) {
        await fs.mkdir(path.dirname(this.storageFile), { recursive: true });
        const tempFile = `${this.storageFile}.${Date.now()}.${Math.random().toString(36).slice(2)}.tmp`;
        try {
            await fs.writeFile(tempFile, buffer);
            await fs.rename(tempFile, this.storageFile);
        } catch (err) {
            try {
                await fs.unlink(tempFile);
            } catch (_) {
                // Ignore temporary file cleanup errors
            }
            throw err;
        }
    }

    /**
     * Encrypts and writes secret string to disk asynchronously.
     * NOTE: Uses official recommended safeStorage.encryptStringAsync to delegate to Windows DPAPI
     * without blocking the Electron Main event loop, using atomic file replacement.
     */
    async saveSecret(secretValue) {
        if (!secretValue || typeof secretValue !== 'string') {
            throw new Error('Secret value must be a non-empty string.');
        }

        await this.ensureEncryptionAvailable();

        const encryptedBuffer = await safeStorage.encryptStringAsync(secretValue);
        await this.writeSecretFile(encryptedBuffer);
    }

    /**
     * Reads and decrypts secret string from disk asynchronously.
     * Handles early missing-file check and key rotation / algorithm upgrades via shouldReEncrypt.
     */
    async loadSecret() {
        // Check and read storage file first; exit early if file does not exist yet
        let encryptedBuffer;
        try {
            encryptedBuffer = await fs.readFile(this.storageFile);
        } catch (err) {
            if (err.code === 'ENOENT') {
                return null; // Vault file does not exist yet; no pre-flight check or decryption needed
            }
            throw err;
        }

        // Vault file exists, ensure encryption subsystem is available before decrypting
        await this.ensureEncryptionAvailable();

        try {
            const { result, shouldReEncrypt } = await safeStorage.decryptStringAsync(encryptedBuffer);

            if (shouldReEncrypt) {
                // Key rotation or encryption upgrade: re-encrypt and persist atomically
                const reEncryptedBuffer = await safeStorage.encryptStringAsync(result);
                await this.writeSecretFile(reEncryptedBuffer);
            }

            return result;
        } catch (err) {
            // Fail-closed on decryption error
            throw new Error('Failed to decrypt secret with Windows DPAPI.');
        }
    }

    /**
     * Deletes the stored credential file as part of normal lifecycle cleanup.
     */
    async deleteSecret() {
        try {
            // Normal application lifecycle deletion.
            // NOTE: Application-level overwriting does not guarantee secure sanitization on modern
            // wear-leveling SSDs or journaling filesystems. If a credential was compromised or exposed,
            // prioritize rotating or revoking the secret rather than relying on disk wiping.
            await fs.unlink(this.storageFile);
        } catch (err) {
            if (err.code !== 'ENOENT') {
                throw err;
            }
        }
    }
}

module.exports = ElectronSecureStore;
```

---

## Key Highlights
1. **Pre-flight & Availability Check**: Calls `await safeStorage.isAsyncEncryptionAvailable()` before performing encryption operations.
2. **Fail-Closed & Temporary Availability**:
   - If encryption is permanently or temporarily unavailable, throws an error or adopts retry/defer strategies.
   - Never falls back to plaintext file persistence (`electron-store`, plain JSON).
3. **Atomic File Write Pattern**: Writes ciphertext to a temporary file before renaming (`fs.rename`) to prevent vault corruption on crash or abrupt shutdown.
4. **Early Missing-File Check**: `loadSecret()` reads the storage file first and returns `null` immediately on `ENOENT`, avoiding unnecessary encryption pre-flight checks when no vault exists.
5. **Async File I/O**: Uses `fs.promises` to avoid blocking the Electron Main process event loop during disk operations.
6. **Official Async safeStorage APIs**:
   - `safeStorage.encryptStringAsync` and `safeStorage.decryptStringAsync` are the current officially recommended APIs for new applications.
   - Decryption returns `{ result, shouldReEncrypt }`, allowing applications to support key rotation and algorithm upgrade workflows transparently when `shouldReEncrypt === true`.
   - Supports proper handling of temporary encryption availability without blocking the Main Process event loop.
   - Synchronous APIs (`encryptString` / `decryptString`) may be progressively deprecated in future Electron releases.
   - Developers should always verify API availability against the official documentation for their specific target Electron version.
7. **Lifecycle Deletion**: Implements standard file cleanup and avoids making misleading claims regarding SSD disk wiping.
