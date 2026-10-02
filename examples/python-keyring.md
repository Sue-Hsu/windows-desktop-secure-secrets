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
from keyring.errors import KeyringError, PasswordDeleteError

SERVICE_NAMESPACE = "MyDesktopApp"
# Windows Credential Manager binary blob limit is 2560 bytes.
# In Python keyring (WinVaultKeyring), strings are stored as UTF-16 (wide characters).
# Therefore, check encoded byte length rather than raw character count.
MAX_CREDENTIAL_BYTES = 2560

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
        
        # Validate UTF-16 encoded byte length against Windows Credential Manager limit
        encoded_bytes = secret_value.encode('utf-16-le')
        if len(encoded_bytes) > MAX_CREDENTIAL_BYTES:
            raise ValueError(
                f"Secret exceeds Windows Credential Manager limit ({len(encoded_bytes)} bytes > {MAX_CREDENTIAL_BYTES} bytes). "
                "Use a DPAPI-protected file for oversized tokens."
            )

        try:
            keyring.set_password(self.service_name, key_name, secret_value)
        except KeyringError as exc:
            # Fail closed: Do not silently store to disk
            raise RuntimeError(f"Could not persist credential '{key_name}' to Windows Vault.") from exc

    # NOTE: 'str | None' type union syntax requires Python 3.10+.
    # For Python < 3.10, use typing.Optional[str].
    def get_credential(self, key_name: str) -> str | None:
        try:
            return keyring.get_password(self.service_name, key_name)
        except KeyringError as exc:
            raise RuntimeError(f"Could not retrieve credential '{key_name}' from Windows Vault.") from exc

    def remove_credential(self, key_name: str) -> None:
        try:
            keyring.delete_password(self.service_name, key_name)
        except PasswordDeleteError:
            # Expected not-found condition: already deleted or never existed
            pass
        except KeyringError as exc:
            # Fail closed: do not silently swallow genuine deletion failures
            raise RuntimeError(f"Failed to delete credential '{key_name}' from Windows Vault.") from exc
```

---

## Key Highlights
1. **Clear Separation**: Only credentials go to Windows Credential Manager; non-sensitive preferences stay in JSON.
2. **Backend Guard**: Checks that `WinVaultKeyring` is the active provider, preventing fallback to plaintext keyring files.
3. **Fail-Closed Deletion Handling**: Specifically catches `PasswordDeleteError` when a credential is already absent, while re-raising any genuine backend failures rather than silently swallowing them.
4. **UTF-16 Capacity Awareness**: Accounts for Windows Credential Manager storing strings as UTF-16, checking byte length rather than assuming 2560 raw characters.
5. **No Local Secret Files**: The filesystem never touches the secret string.
