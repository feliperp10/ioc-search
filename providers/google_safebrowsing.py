import requests

from providers.base import BaseProvider


class GoogleSafeBrowsingProvider(BaseProvider):
    name = "GoogleSafeBrowsing"
    supported_types = ["url"]
    BASE_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    def _query(self, ioc, ioc_type):
        target = ioc if "://" in ioc else f"http://{ioc}"

        body = {
            "client": {"clientId": "ioc-search-tool", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": target}],
            },
        }

        resp = requests.post(
            self.BASE_URL, params={"key": self.api_key}, json=body, timeout=15
        )
        resp.raise_for_status()
        matches = resp.json().get("matches", [])

        verdict = matches[0].get("threatType", "malicious").lower() if matches else "clean"

        return {
            "verdict": verdict,
            "matches_found": len(matches),
        }
