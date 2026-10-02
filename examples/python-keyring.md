# Example: Python Desktop Credential Storage with `keyring`

This example demonstrates how a Python Windows desktop application (PyQt, PySide, Tkinter, wxPython) can leverage the standard `keyring` library to securely interface with the **Windows Credential Manager**.

---

## Scenario
A Python desktop utility connects to a cloud API using an API key and a refresh token.
- Ordinary configuration (window width, theme) is stored in a standard `settings.json`.
- Secrets (API key and tokens) are stored in the Windows Credential Manager.

---

## Implementation (`secure_credentials.py`)

```python
import keyring
from keyring.backends.Windows import WinVaultKeyring
from keyring.errors import KeyringError

SERVICE_NAMESPACE = "MyDesktopApp"

class WindowsCredentialVault:
    def __init__(self, service_name: str = SERVICE_NAMESPACE):
        self.service_name = service_name
        self._verify_backend()

    def _verify_backend(self):
        backend = keyring.get_keyring()
        # Verify that the active backend is indeed Windows Credential Manager
        if not isinstance(backend, WinVaultKeyring):
            # FAIL-CLOSED: Refuse to fallback silently to insecure keyrings (e.g. plain text file)
            raise RuntimeError(
                f"Insecure keyring backend detected: {backend}. Expected Windows Credential Manager."
            )

    def set_credential(self, key_name: str, secret_value: str) -> None:
        if not secret_value:
            raise ValueError("Secret value cannot be empty.")
        
        try:
            keyring.set_password(self.service_name, key_name, secret_value)
        except KeyringError as exc:
            # Fail closed: Do not silently store to disk
            raise RuntimeError(f"Could not persist credential '{key_name}' to Windows Vault.") from exc

    def get_credential(self, key_name: str) -> str | None:
        try:
            return keyring.get_password(self.service_name, key_name)
        except KeyringError as exc:
            raise RuntimeError(f"Could not retrieve credential '{key_name}' from Windows Vault.") from exc

    def remove_credential(self, key_name: str) -> None:
        try:
            keyring.delete_password(self.service_name, key_name)
        except KeyringError:
            pass  # Already deleted
```

---

## Key Highlights
1. **Clear Separation**: Only credentials go to Windows Credential Manager; non-sensitive preferences stay in JSON.
2. **Backend Guard**: Checks that `WinVaultKeyring` is the active provider, preventing fallback to plaintext keyring files.
3. **No Local Secret Files**: The file system never touches the secret string.
