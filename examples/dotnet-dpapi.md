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
    // Optional app-specific secondary entropy to increase defense against other processes in the same user session
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
            // Wipe intermediate plaintext buffer from memory
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
    /// Deletes the credential on logout.
    /// </summary>
    public void DeleteSecret()
    {
        if (File.Exists(_storagePath))
        {
            // Overwrite file contents before deleting (secure erase)
            File.WriteAllBytes(_storagePath, new byte[64]);
            File.Delete(_storagePath);
        }
    }
}
```

---

## Key Highlights
1. **Scope Selection**: Uses `DataProtectionScope.CurrentUser` so other Windows accounts on the same computer cannot decrypt the payload.
2. **Fail-Closed**: Exceptions are thrown rather than silently continuing with plaintext files.
3. **Memory Hygiene**: Arrays containing plaintext bytes are zeroed out via `Array.Clear` in the `finally` block.
