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

            // Ensure destination directory exists before attempting write
            string directory = Path.GetDirectoryName(_storagePath);
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }

            // Write to temporary file first and atomically replace to avoid partial/corrupted writes on crash
            string tempFile = _storagePath + "." + Guid.NewGuid().ToString("N") + ".tmp";
            File.WriteAllBytes(tempFile, encryptedBytes);
            File.Move(tempFile, _storagePath, overwrite: true);
        }
        catch (CryptographicException ex)
        {
            // FAIL-CLOSED: Explicit error on DPAPI failure
            throw new InvalidOperationException("Failed to securely protect credential via Windows DPAPI.", ex);
        }
        catch (IOException ex)
        {
            // Filesystem / disk write failure
            throw new InvalidOperationException("Failed to persist protected credential to disk due to an I/O error.", ex);
        }
        catch (UnauthorizedAccessException ex)
        {
            // Permission denial
            throw new InvalidOperationException("Permission denied when writing protected credential to disk.", ex);
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
            // RECOVERY FLOW:
            // Decryption failures occur when:
            // 1. The Windows user account password was reset by an admin without providing the old password.
            // 2. The user profile or storage file was migrated to a different machine or user SID.
            // 3. The ciphertext file was corrupted.
            //
            // Fail-closed: Never fall back to plaintext. Prompt the user to re-authenticate and establish
            // a fresh credential. If needed, provide an application option to purge the invalid ciphertext.
            throw new InvalidOperationException(
                "Decryption failed. DPAPI binding may be invalid or corrupted; user re-authentication required.",
                ex
            );
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
2. **Fail-Closed Principle**: Exceptions are thrown rather than silently continuing with plaintext files.
3. **Atomic-ish Persistence**: Writes to a uniquely named temporary file before moving into place, preventing partial/corrupted ciphertext writes during unexpected application terminations.
4. **Specific Error Differentiation**: Distinguishes `CryptographicException` from filesystem `IOException` and permission errors.
5. **Recovery Flow Guidance**: Documents clear recovery steps (prompt for re-authentication and purge invalid ciphertext) when DPAPI decryption fails after Windows credential or profile changes.
6. **Modern .NET Dependency**: `System.Security.Cryptography.ProtectedData` is a Windows-only API. In modern cross-platform .NET (.NET 6/7/8/9), ensure the `System.Security.Cryptography.ProtectedData` NuGet package is referenced.
7. **Memory Hygiene Boundaries**: Uses `Array.Clear` to zero out intermediate byte buffers, explicitly documenting that immutable strings cannot be reliably zeroized in managed runtimes.
8. **Lifecycle Deletion**: Implements normal file removal and highlights provider-side revocation over unreliable application-level disk wiping.
