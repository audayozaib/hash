import aiohttp
import json
from typing import Dict, Any
from .config import settings

class OllamaClient:
    def __init__(self):
        self.host = settings.OLLAMA_HOST
        self.model = settings.OLLAMA_MODEL
        self.api_url = f"{self.host}/api/generate"
    
    async def analyze_malware(self, scan_results: Dict[str, Any]) -> str:
        """تحليل نتائج الفحص وتوليد تقرير"""
        
        # بناء السياق للـ AI
        context = self._build_context(scan_results)
        
        prompt = f"""You are a cybersecurity malware analyst. Analyze the following malware scan results and provide a detailed report in Arabic.

{context}

Please provide:
1. ملخص تنفيذي (Executive Summary)
2. تقييم الخطورة (Critical/High/Medium/Low)
3. تحليل السلوك الضار المحتمل
4. مؤشرات الاختراق (IOCs) المستخرجة
5. التوقيعات والأنماط المكتشفة
6. التوصيات الأمنية

اكتب التقرير باللغة العربية الفصحى مع المصطلحات التقنية بالإنجليزية بين قوسين."""

        try:
            async with aiohttp.ClientSession() as session:
                payload = {
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.3,
                        "num_predict": 2000
                    }
                }
                
                async with session.post(self.api_url, json=payload) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get("response", "No response from AI model")
                    else:
                        return f"Error: Ollama API returned status {response.status}"
                        
        except Exception as e:
            return f"Error connecting to Ollama: {str(e)}\n\nPlease ensure Ollama is running and accessible."
    
    def _build_context(self, results: Dict[str, Any]) -> str:
        """بناء سياق النتائج للتحليل"""
        
        # VirusTotal summary
        vt = results.get("virustotal", {})
        vt_summary = f"""
VirusTotal Results:
- Detection Ratio: {vt.get('detection_ratio', 'N/A')}
- Malicious: {vt.get('malicious_count', 0)}
- Suspicious: {vt.get('suspicious_count', 0)}
- File Type: {vt.get('type_description', 'Unknown')}
"""
        
        # YARA matches
        yara_matches = results.get("yara", [])
        yara_summary = "YARA Rules Triggered:\n"
        if yara_matches:
            for match in yara_matches:
                yara_summary += f"- {match.get('rule_name')}: {match.get('meta', {}).get('description', 'No description')}\n"
        else:
            yara_summary += "- No YARA rules matched\n"
        
        # Strings
        strings = results.get("strings", [])[:20]  # أول 20 فقط
        strings_summary = f"\nNotable Strings Found ({len(strings)} samples):\n"
        for s in strings[:10]:
            strings_summary += f"- {s[:100]}\n"
        
        # FLOSS
        floss = results.get("floss", [])
        floss_summary = f"\nFLOSS Deobfuscated Strings ({len(floss)} found):\n"
        for f in floss[:5]:
            floss_summary += f"- {f[:100]}\n"
        
        # File hashes
        hashes = results.get("hashes", {})
        
        return f"""
File: {results.get('filename')}
SHA256: {hashes.get('sha256', 'N/A')}
MD5: {hashes.get('md5', 'N/A')}

{vt_summary}

{yara_summary}

{strings_summary}

{floss_summary}
"""