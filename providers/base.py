import requests


class BaseProvider:
    """Base class for all Threat Intelligence providers.

    Each concrete provider must define:
      - name: display name (e.g. "VirusTotal")
      - supported_types: list of supported IOC types
                          (e.g. ["ipv4", "ipv6", "url", "md5", "sha1", "sha256"])
      - _query(self, ioc, ioc_type): performs the HTTP call and returns a result dict
    """

    name = "Base"
    supported_types = []

    def __init__(self, api_key):
        self.api_key = api_key

    def is_supported(self, ioc_type):
        return ioc_type in self.supported_types

    def fetch(self, ioc, ioc_type):
        """Single entry point used by cli.py. Never lets an exception escape."""
        if not self.api_key:
            return {
                "provider": self.name,
                "status": "error",
                "error": "API key not configured (check your .env)",
            }

        if not self.is_supported(ioc_type):
            return {"provider": self.name, "status": "skipped"}

        try:
            result = self._query(ioc, ioc_type)
            result.setdefault("provider", self.name)
            result.setdefault("status", "success")
            return result
        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code if e.response is not None else "?"
            detail = ""
            if e.response is not None:
                try:
                    detail = f" - {e.response.text[:200]}"
                except Exception:
                    pass
            return {
                "provider": self.name,
                "status": "error",
                "error": f"HTTP {status_code}{detail}",
            }
        except requests.exceptions.RequestException as e:
            return {"provider": self.name, "status": "error", "error": str(e)}
        except Exception as e:  # never let one provider crash the whole scan
            return {"provider": self.name, "status": "error", "error": str(e)}

    def _query(self, ioc, ioc_type):
        raise NotImplementedError
