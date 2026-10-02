# Example: .NET / C# DPAPI Secure Storage

This example demonstrates how to implement secure credential storage in a C# Windows desktop application (WPF, WinForms, WinUI 3, or Avalonia) using Windows DPAPI (`ProtectedData`).

---

## Scenario
A desktop application requires an API key to communicate with an external AI service. 
- The user inputs the key via the UI.
- The key must be encrypted before persisting to `%APPDATA%`.
- If DPAPI fails, the app must **fail closed** rather than falling back to plaintext JSON.

---

## Implementation

```csharp
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public class SecureCredentialStore
{
    // Optional application-specific entropy for namespacing / accidental cross-use prevention.
    // NOTE: This hardcoded entropy is NOT a secret and does NOT protect against same-user malicious processes.
    // For true defense-in-depth, supply user-provided entropy (e.g., PIN/passphrase) or pass null for standard DPAPI.
    private static readonly byte[] OptionalEntropy = Encoding.UTF8.GetBytes("Application-Specific-Entropy-V1");

    private readonly string _storagePath;

    public SecureCredentialStore(string appDataDirectory)
    {
        _storagePath = Path.Combine(appDataDirectory, "credentials.dat");
    }

    /// <summary>
    /// Encrypts and stores the secret using Windows DPAPI CurrentUser scope.
    /// </summary>
    public void StoreSecret(string secret)
    {
        if (string.IsNullOrWhiteSpace(secret))
        {
            throw new ArgumentException("Secret cannot be empty.", nameof(secret));
        }

        byte[] plainBytes = Encoding.UTF8.GetBytes(secret);

        try
        {
            // Protect using CurrentUser scope: only this Windows user account can decrypt
            byte[] encryptedBytes = ProtectedData.Protect(
                plainBytes,
                OptionalEntropy,
                DataProtectionScope.CurrentUser
            );

            // Write binary payload to disk - never plaintext
            File.WriteAllBytes(_storagePath, encryptedBytes);
        }
        catch (Exception ex)
        {
            // FAIL-CLOSED: Explicit error, never fall back to plaintext file
            throw new InvalidOperationException("Failed to securely protect credential via Windows DPAPI.", ex);
        }
        finally
        {
            // Clear intermediate plaintext byte buffer to reduce exposure window
            Array.Clear(plainBytes, 0, plainBytes.Length);
        }
    }

    /// <summary>
    /// Reads and decrypts the secret.
    /// </summary>
    public string LoadSecret()
    {
        if (!File.Exists(_storagePath))
        {
            return null;
        }

        byte[] encryptedBytes = File.ReadAllBytes(_storagePath);

        try
        {
            byte[] decryptedBytes = ProtectedData.Unprotect(
                encryptedBytes,
                OptionalEntropy,
                DataProtectionScope.CurrentUser
            );

            // Convert to string for application consumption.
            // NOTE: Array.Clear clears this specific intermediate byte buffer, but the resulting
            // System.String remains in managed heap until garbage collected. For higher security,
            // consume credentials directly as byte[] / ReadOnlySpan<byte> and clear immediately after use.
            string secret = Encoding.UTF8.GetString(decryptedBytes);
            Array.Clear(decryptedBytes, 0, decryptedBytes.Length);
            return secret;
        }
        catch (CryptographicException ex)
        {
            // Fail-closed if the key was corrupted or accessed by a different user
            throw new InvalidOperationException("Decryption failed. The secret cannot be retrieved.", ex);
        }
    }

    /// <summary>
    /// Deletes the credential file on logout as part of normal lifecycle cleanup.
    /// </summary>
    public void DeleteSecret()
    {
        if (File.Exists(_storagePath))
        {
            // Normal application lifecycle deletion.
            // NOTE: Application-level file overwriting cannot guarantee secure erasure on modern
            // wear-leveling SSDs or journaling filesystems. If a credential was compromised or exposed,
            // prioritize rotating or revoking the secret rather than relying on disk wiping.
            File.Delete(_storagePath);
        }
    }
}
```

---

## Key Highlights
1. **Scope Selection**: Uses `DataProtectionScope.CurrentUser` so other Windows accounts on the same computer cannot decrypt the payload.
2. **Fail-Closed**: Exceptions are thrown rather than silently continuing with plaintext files.
3. **Entropy Clarification**: Demonstrates namespacing entropy, clearly noting it does not replace user-supplied secrets or prevent same-user malicious process inspection.
4. **Memory Hygiene Boundaries**: Uses `Array.Clear` to zero out intermediate byte buffers, explicitly documenting that immutable strings cannot be reliably zeroized in managed runtimes.
5. **Lifecycle Deletion**: Implements normal file removal and highlights provider-side revocation over unreliable application-level disk wiping.
