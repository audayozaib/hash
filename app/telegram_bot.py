import aiohttp
from typing import Dict, Any
from .config import settings

class TelegramNotifier:
    def __init__(self):
        self.bot_token = settings.TELEGRAM_BOT_TOKEN
        self.chat_id = settings.TELEGRAM_CHAT_ID
        self.base_url = f"https://api.telegram.org/bot{self.bot_token}"
    
    async def send_report(self, results: Dict[str, Any]) -> bool:
        """إرسال التقرير إلى Telegram"""
        if not self.bot_token or not self.chat_id:
            print("[-] Telegram credentials not configured")
            return False
        
        try:
            # إنشاء ملخص مختصر
            message = self._format_message(results)
            
            # إرسال الرسالة النصية
            await self._send_message(message)
            
            # إرسال التقرير الكامل كملف إذا كان طويلاً
            if len(results.get("ai_report", "")) > 4000:
                await self._send_document(results)
            
            return True
            
        except Exception as e:
            print(f"[-] Telegram send error: {e}")
            return False
    
    def _format_message(self, results: Dict[str, Any]) -> str:
        """تنسيق الرسالة لـ Telegram"""
        hashes = results.get("hashes", {})
        vt = results.get("virustotal", {})
        yara_count = len(results.get("yara", []))
        
        # تحديد الإيموجي حسب الخطورة
        malicious = vt.get("malicious_count", 0)
        if malicious > 10:
            severity = "🔴 CRITICAL"
        elif malicious > 3:
            severity = "🟠 HIGH"
        elif malicious > 0:
            severity = "🟡 MEDIUM"
        else:
            severity = "🟢 LOW"
        
        message = f"""
🛡️ <b>Malware Scan Report</b>

📁 <b>File:</b> <code>{results.get('filename', 'Unknown')}</code>
⚡ <b>Severity:</b> {severity}

🔐 <b>Hashes:</b>
<code>MD5:    {hashes.get('md5', 'N/A')}</code>
<code>SHA1:   {hashes.get('sha1', 'N/A')}</code>
<code>SHA256: {hashes.get('sha256', 'N/A')}</code>

🌐 <b>VirusTotal:</b>
• Detection: {vt.get('detection_ratio', 'N/A')}
• Type: {vt.get('type_description', 'Unknown')}
• <a href="{vt.get('permalink', '#')}">View on VT</a>

🎯 <b>YARA Matches:</b> {yara_count} rules

📊 <b>Strings Extracted:</b>
• Standard: {len(results.get('strings', []))}
• FLOSS: {len(results.get('floss', []))}

🤖 <b>AI Analysis:</b> {'Completed ✅' if results.get('ai_report') else 'Failed ❌'}

<i>Full report sent as document...</i>
"""
        return message
    
    async def _send_message(self, text: str):
        """إرسال رسالة نصية"""
        url = f"{self.base_url}/sendMessage"
        
        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload) as response:
                if response.status != 200:
                    print(f"Telegram API error: {await response.text()}")
    
    async def _send_document(self, results: Dict[str, Any]):
        """إرسال التقرير الكامل كملف"""
        import tempfile
        import os
        
        # إنشاء ملف مؤقت
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as f:
            f.write(f"MALWARE ANALYSIS REPORT\n")
            f.write(f"{'='*50}\n\n")
            f.write(f"File: {results.get('filename')}\n")
            f.write(f"SHA256: {results.get('hashes', {}).get('sha256')}\n\n")
            f.write(f"VIRUSTOTAL RESULTS:\n{results.get('virustotal')}\n\n")
            f.write(f"YARA MATCHES:\n{results.get('yara')}\n\n")
            f.write(f"AI ANALYSIS:\n{results.get('ai_report')}\n")
            temp_path = f.name
        
        try:
            url = f"{self.base_url}/sendDocument"
            
            with open(temp_path, 'rb') as doc:
                data = aiohttp.FormData()
                data.add_field('chat_id', self.chat_id)
                data.add_field('document', doc, filename=f"report_{results.get('hashes', {}).get('sha256', 'unknown')[:16]}.txt")
                data.add_field('caption', 'Detailed Malware Analysis Report')
                
                async with aiohttp.ClientSession() as session:
                    async with session.post(url, data=data) as response:
                        if response.status != 200:
                            print(f"Document send error: {await response.text()}")
        finally:
            os.unlink(temp_path)