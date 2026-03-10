import hashlib
import os
import tempfile
from typing import Dict, Any
from pathlib import Path

from .config import settings
from .virustotal import VirusTotalClient
from .yara_engine import YaraEngine
from .strings_extractor import StringsExtractor
from .ollama_client import OllamaClient
from .telegram_bot import TelegramNotifier

class MalwareScanner:
    def __init__(self):
        self.vt_client = VirusTotalClient()
        self.yara_engine = YaraEngine()
        self.strings_extractor = StringsExtractor()
        self.ollama = OllamaClient()
        self.telegram = TelegramNotifier()
    
    def calculate_hashes(self, file_path: str) -> Dict[str, str]:
        """حساب هاشات الملف المتعددة"""
        hashes = {}
        md5_hash = hashlib.md5()
        sha1_hash = hashlib.sha1()
        sha256_hash = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                md5_hash.update(chunk)
                sha1_hash.update(chunk)
                sha256_hash.update(chunk)
        
        return {
            "md5": md5_hash.hexdigest(),
            "sha1": sha1_hash.hexdigest(),
            "sha256": sha256_hash.hexdigest()
        }
    
    async def scan_file(self, file_path: str, filename: str) -> Dict[str, Any]:
        """الفحص الشامل للملف"""
        results = {
            "filename": filename,
            "file_path": file_path,
            "hashes": {},
            "virustotal": {},
            "yara": [],
            "strings": [],
            "floss": [],
            "ai_report": "",
            "status": "pending"
        }
        
        try:
            # 1. حساب الهاشات
            print(f"[+] Calculating hashes for {filename}...")
            results["hashes"] = self.calculate_hashes(file_path)
            
            # 2. فحص VirusTotal
            print(f"[+] Querying VirusTotal...")
            results["virustotal"] = await self.vt_client.check_hash(
                results["hashes"]["sha256"]
            )
            
            # 3. فحص YARA
            print(f"[+] Running YARA scan...")
            results["yara"] = self.yara_engine.scan_file(file_path)
            
            # 4. استخراج النصوص العادية
            print(f"[+] Extracting strings...")
            results["strings"] = self.strings_extractor.extract_strings(file_path)
            
            # 5. استخراج النصوص المشوهة بـ FLOSS
            print(f"[+] Running FLOSS analysis...")
            results["floss"] = await self.strings_extractor.extract_floss(file_path)
            
            # 6. توليد تقرير AI
            print(f"[+] Generating AI report...")
            results["ai_report"] = await self.ollama.analyze_malware(results)
            
            # 7. إرسال إلى Telegram
            print(f"[+] Sending to Telegram...")
            await self.telegram.send_report(results)
            
            results["status"] = "completed"
            
        except Exception as e:
            results["status"] = "error"
            results["error"] = str(e)
            print(f"[-] Error during scan: {e}")
        
        return results