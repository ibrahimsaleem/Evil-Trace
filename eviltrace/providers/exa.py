import os
import requests
import datetime
import re

class ExaProvider:
    """Provider for querying Exa Search API (threat intelligence enrichment)."""
    
    name = "exa"

    def __init__(self, api_key: str = ""):
        self._api_key = api_key or os.environ.get("EXA_API_KEY", "")

    def is_available(self) -> bool:
        return bool(self._api_key)

    def _sanitize(self, text: str) -> str:
        if not self._api_key:
            return text
        text = text.replace(self._api_key, "***")
        text = re.sub(r"key=[A-Za-z0-9_\-]+", "key=***", text)
        return text

    def enrich_ioc(self, ioc: str, ioc_type: str) -> dict:
        """Query Exa search for threat intelligence on a given IOC."""
        if not self.is_available():
            raise ValueError("Exa API key is missing")

        # Formulate query
        if ioc_type == "ip":
            query = f"threat intelligence malicious IP {ioc}"
        elif ioc_type == "domain":
            query = f"threat intelligence malicious domain {ioc}"
        elif ioc_type == "url":
            query = f"threat intelligence malicious URL {ioc}"
        elif ioc_type == "hash":
            query = f"threat intelligence file hash {ioc}"
        else:
            query = f"threat intelligence indicator {ioc}"

        headers = {
            "x-api-key": self._api_key,
            "content-type": "application/json"
        }
        
        payload = {
            "query": query,
            "numResults": 1,
            "contents": {
                "highlights": True
            }
        }

        try:
            resp = requests.post(
                "https://api.exa.ai/search",
                json=payload,
                headers=headers,
                timeout=15
            )
            
            # Sanitize the error message if response is not 200
            resp.raise_for_status()
            data = resp.json()
            
            results = data.get("results", [])
            if not results:
                return {
                    "ioc": ioc,
                    "ioc_type": ioc_type,
                    "query_used": query,
                    "external_context_summary": "No public threat intelligence details found in Exa.",
                    "source_title": "N/A",
                    "source_url": "N/A",
                    "source_highlight": "N/A",
                    "confidence": "unknown",
                    "enrichment_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "provider": "exa"
                }

            top_result = results[0]
            title = top_result.get("title") or "N/A"
            url = top_result.get("url") or "N/A"
            score = top_result.get("score", 0.0)
            
            highlights = top_result.get("highlights", [])
            highlight = highlights[0] if highlights else "N/A"
            
            # Determine confidence
            if score >= 0.8:
                confidence = "supportive"
            elif score >= 0.5:
                confidence = "informational"
            else:
                confidence = "unknown"

            summary = f"Threat intelligence reference: {title} ({url})"

            return {
                "ioc": ioc,
                "ioc_type": ioc_type,
                "query_used": query,
                "external_context_summary": summary,
                "source_title": title,
                "source_url": url,
                "source_highlight": highlight,
                "confidence": confidence,
                "enrichment_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "provider": "exa"
            }
        except Exception as e:
            # Mask key in any raised or logged exception text
            sanitized_error = self._sanitize(str(e))
            raise RuntimeError(f"Exa search failed: {sanitized_error}")
