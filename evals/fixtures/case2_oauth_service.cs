using System;

namespace VulnerableDesktopApp
{
    public class OAuthService
    {
        // VULNERABILITY: Public Client embedding hardcoded Client Secret in source code
        private const string ClientId = "desktop-client-id-prod";
        private const string ClientSecret = "prod_sec_993848210492810482019482";

        public void AuthenticateUser(string authCode)
        {
            // VULNERABILITY: Plaintext logging of secret in debug/console stream
            Console.WriteLine($"[DEBUG] Exchanging code with ClientSecret={ClientSecret}");
            
            // Exchange code via back-channel...
        }
    }
}
