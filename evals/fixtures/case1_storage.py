import os
import json

class CloudSettings:
    """
    VULNERABLE TEST FIXTURE (Case 1):
    Directly writes third-party API key to plaintext JSON file in AppData.
    """
    def __init__(self):
        self.config_dir = os.path.expandvars(r"%APPDATA%\MockCloudApp")
        os.makedirs(self.config_dir, exist_ok=True)
        self.config_file = os.path.join(self.config_dir, "config.json")

    def save_api_key(self, api_key: str):
        # VULNERABILITY: Plaintext persistence in user data directory
        data = {"provider_api_key": api_key, "theme": "dark"}
        with open(self.config_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
