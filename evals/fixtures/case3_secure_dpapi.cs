using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace SecureDesktopApp
{
    public class SecureTokenStore
    {
        private readonly string _storagePath;

        public SecureTokenStore(string storagePath)
        {
            _storagePath = storagePath;
        }

        public void SaveToken(string token)
        {
            if (string.IsNullOrEmpty(token)) throw new ArgumentNullException(nameof(token));

            byte[] plainBytes = Encoding.UTF8.GetBytes(token);
            try
            {
                // SECURE: Encrypted using DPAPI CurrentUser before writing to disk
                byte[] cipherBytes = ProtectedData.Protect(
                    plainBytes,
                    null,
                    DataProtectionScope.CurrentUser
                );

                string dir = Path.GetDirectoryName(_storagePath);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

                string tempFile = $"{_storagePath}.{Guid.NewGuid():N}.tmp";
                File.WriteAllBytes(tempFile, cipherBytes);
                File.Move(tempFile, _storagePath, overwrite: true);
            }
            finally
            {
                Array.Clear(plainBytes, 0, plainBytes.Length);
            }
        }

        public string LoadToken()
        {
            if (!File.Exists(_storagePath)) return null;

            byte[] cipherBytes = File.ReadAllBytes(_storagePath);
            try
            {
                byte[] plainBytes = ProtectedData.Unprotect(
                    cipherBytes,
                    null,
                    DataProtectionScope.CurrentUser
                );
                string token = Encoding.UTF8.GetString(plainBytes);
                Array.Clear(plainBytes, 0, plainBytes.Length);
                return token;
            }
            catch (CryptographicException)
            {
                // FAIL-CLOSED & RECOVERY FLOW: Returns null and signals re-authentication required; no fallback to plaintext
                return null;
            }
        }
    }
}
