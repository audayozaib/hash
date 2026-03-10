import aiohttp
import asyncio
from typing import Dict, Any
from .config import settings

class VirusTotalClient:
    def __init__(self):
        self.api_key = settings.VIRUSTOTAL_API_KEY
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
    
    async def check_hash(self, file_hash: str) -> Dict[str, Any]:
        """التحقق من الهاش في VirusTotal"""
        if not self.api_key:
            return {"error": "VirusTotal API key not configured"}
        
        url = f"{self.base_url}/files/{file_hash}"
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=self.headers) as response:
                if response.status == 200:
                    data = await response.json()
                    attributes = data.get("data", {}).get("attributes", {})
                    
                    last_analysis = attributes.get("last_analysis_stats", {})
                    detection_ratio = f"{last_analysis.get('malicious', 0)}/{sum(last_analysis.values())}"
                    
                    return {
                        "found": True,
                        "detection_ratio": detection_ratio,
                        "malicious_count": last_analysis.get("malicious", 0),
                        "suspicious_count": last_analysis.get("suspicious", 0),
                        "harmless_count": last_analysis.get("harmless", 0),
                        "undetected_count": last_analysis.get("undetected", 0),
                        "names": attributes.get("names", [])[:5],  # أول 5 أسماء
                        "type_description": attributes.get("type_description", "Unknown"),
                        "reputation": attributes.get("reputation", 0),
                        "last_analysis_date": attributes.get("last_analysis_date"),
                        "permalink": f"https://www.virustotal.com/gui/file/{file_hash}"
                    }
                elif response.status == 404:
                    return {
                        "found": False,
                        "message": "File not found in VirusTotal database"
                    }
                else:
                    return {
                        "error": f"API returned status {response.status}"
                    }