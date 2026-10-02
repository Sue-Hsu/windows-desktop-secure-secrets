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
     */
    async ensureEncryptionAvailable() {
        if (!(await safeStorage.isAsyncEncryptionAvailable())) {
            // FAIL-CLOSED: Stop immediately instead of silent plaintext fallback
            throw new Error('OS-level encryption is not available. Operation aborted.');
        }
    }

    /**
     * Encrypts and writes secret string to disk asynchronously.
     * NOTE: Uses official recommended safeStorage.encryptStringAsync to delegate to Windows DPAPI
     * without blocking the Electron Main event loop.
     */
    async saveSecret(secretValue) {
        if (!secretValue || typeof secretValue !== 'string') {
            throw new Error('Secret value must be a non-empty string.');
        }

        await this.ensureEncryptionAvailable();

        const encryptedBuffer = await safeStorage.encryptStringAsync(secretValue);
        await fs.writeFile(this.storageFile, encryptedBuffer);
    }

    /**
     * Reads and decrypts secret string from disk asynchronously.
     * Handles key rotation / algorithm upgrades via shouldReEncrypt.
     */
    async loadSecret() {
        await this.ensureEncryptionAvailable();

        try {
            const encryptedBuffer = await fs.readFile(this.storageFile);
            const { result, shouldReEncrypt } = await safeStorage.decryptStringAsync(encryptedBuffer);

            if (shouldReEncrypt) {
                // Key rotation or encryption upgrade: re-encrypt and persist transparently
                const reEncryptedBuffer = await safeStorage.encryptStringAsync(result);
                await fs.writeFile(this.storageFile, reEncryptedBuffer);
            }

            return result;
        } catch (err) {
            if (err.code === 'ENOENT') {
                return null; // File does not exist yet
            }
            // Fail-closed on decryption error or file read issue
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
1. **Pre-flight Check**: Calls `await safeStorage.isAsyncEncryptionAvailable()` to verify temporary encryption availability before performing operations.
2. **Fail-Closed Principle**: If encryption is unavailable, throws an error rather than writing plain text.
3. **Async File I/O**: Uses `fs.promises` to avoid blocking the Electron Main process during disk writes and reads.
4. **Official Async safeStorage APIs**:
   - `safeStorage.encryptStringAsync` and `safeStorage.decryptStringAsync` are the current officially recommended APIs for new applications.
   - Decryption returns `{ result, shouldReEncrypt }`, allowing applications to support key rotation and algorithm upgrade workflows transparently when `shouldReEncrypt === true`.
   - Supports proper handling of temporary encryption availability without blocking the Main Process event loop.
   - Synchronous APIs (`encryptString` / `decryptString`) may be progressively deprecated in future Electron releases.
   - Developers should always verify API availability against the official documentation for their specific target Electron version.
5. **Lifecycle Deletion**: Implements standard file cleanup and avoids making misleading claims regarding SSD disk wiping.
