# Example: Godot Engine 4.x Desktop Credential Security

This example addresses the common misconception that Godot's `user://` virtual directory is a secure storage sandbox, and illustrates how to safely handle sensitive credentials on Windows desktop exports.

---

## The Reality of `user://`
- On Windows, `user://` maps directly to `%APPDATA%\Godot\app_userdata\<Project-Name>\`.
- Standard calls like `FileAccess.open("user://secrets.json", FileAccess.WRITE)` store data in **unprotected, plaintext text files**.
- Any application running with standard user rights can read these files.

---

## Recommended Godot Solution (C# / .NET)

If using Godot with C#/.NET, use Windows DPAPI directly via `System.Security.Cryptography.ProtectedData`:

```csharp
using Godot;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public partial class SecureAuthManager : Node
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("Game-Specific-Entropy-Salt");

    public static void SaveAuthToken(string token)
    {
        // Obtain actual OS filesystem path from Godot's virtual path
        string globalPath = ProjectSettings.GlobalizePath("user://auth.dat");
        byte[] plainBytes = Encoding.UTF8.GetBytes(token);

        try
        {
            byte[] cipherBytes = ProtectedData.Protect(
                plainBytes,
                Entropy,
                DataProtectionScope.CurrentUser
            );
            File.WriteAllBytes(globalPath, cipherBytes);
        }
        catch (Exception ex)
        {
            // FAIL-CLOSED: Refuse to write plaintext
            GD.PrintErr($"[Security Error] Failed to encrypt auth token: {ex.Message}");
            throw;
        }
        finally
        {
            Array.Clear(plainBytes, 0, plainBytes.Length);
        }
    }

    public static string LoadAuthToken()
    {
        string globalPath = ProjectSettings.GlobalizePath("user://auth.dat");
        if (!File.Exists(globalPath)) return null;

        byte[] cipherBytes = File.ReadAllBytes(globalPath);
        try
        {
            byte[] plainBytes = ProtectedData.Unprotect(
                cipherBytes,
                Entropy,
                DataProtectionScope.CurrentUser
            );
            string token = Encoding.UTF8.GetString(plainBytes);
            Array.Clear(plainBytes, 0, plainBytes.Length);
            return token;
        }
        catch (Exception ex)
        {
            GD.PrintErr($"[Security Error] Failed to decrypt auth token: {ex.Message}");
            return null;
        }
    }
}
```

---

## Alternative for Pure GDScript (Session-Only Fallback)
If you cannot use C# or compile a C++ GDExtension binding to `Crypt32.dll`:
- **DO NOT** write the API key or password to `user://config.cfg`.
- **DO** keep the credential in a transient in-memory variable (`var runtime_token = ""`).
- Prompt the user to log in or enter their key each session, or prompt for a user-supplied Master Password to derive a local encryption key.
