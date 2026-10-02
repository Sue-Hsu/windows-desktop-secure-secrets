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
const fs = require('fs');
const path = require('path');

class ElectronSecureStore {
    constructor() {
        this.storageFile = path.join(app.getPath('userData'), 'vault.bin');
    }

    /**
     * Checks whether OS-level encryption is available on the current Windows installation.
     */
    ensureEncryptionAvailable() {
        if (!safeStorage.isEncryptionAvailable()) {
            // FAIL-CLOSED: Stop immediately instead of silent plaintext fallback
            throw new Error('OS-level encryption is not available. Operation aborted.');
        }
    }

    /**
     * Encrypts and writes secret string to disk.
     */
    saveSecret(secretValue) {
        if (!secretValue || typeof secretValue !== 'string') {
            throw new Error('Secret value must be a non-empty string.');
        }

        this.ensureEncryptionAvailable();

        // safeStorage encrypts using Windows DPAPI (CurrentUser)
        const encryptedBuffer = safeStorage.encryptString(secretValue);
        fs.writeFileSync(this.storageFile, encryptedBuffer);
    }

    /**
     * Reads and decrypts secret string from disk.
     */
    loadSecret() {
        if (!fs.existsSync(this.storageFile)) {
            return null;
        }

        this.ensureEncryptionAvailable();

        const encryptedBuffer = fs.readFileSync(this.storageFile);
        try {
            return safeStorage.decryptString(encryptedBuffer);
        } catch (err) {
            // Fail-closed on decryption error
            throw new Error('Failed to decrypt secret with Windows DPAPI.');
        }
    }

    /**
     * Safely wipes and removes the stored secret.
     */
    deleteSecret() {
        if (fs.existsSync(this.storageFile)) {
            fs.writeFileSync(this.storageFile, Buffer.alloc(32)); // overwrite
            fs.unlinkSync(this.storageFile);
        }
    }
}

module.exports = ElectronSecureStore;
```

---

## Key Highlights
1. **Pre-flight Check**: Calls `safeStorage.isEncryptionAvailable()` before attempting encryption.
2. **Fail-Closed Principle**: If encryption is unavailable, throws an error rather than writing plain text.
3. **Data Protection**: Encrypted binary buffer is safe against offline analysis and cross-user snooping.
