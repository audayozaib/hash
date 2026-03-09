#!/usr/bin/env python3
"""
Telegram Bot Malware Scanner for Railway
بوت تلغرام لفحص الملفات الخبيثة
"""

import os
import hashlib
import json
import requests
import re
import tempfile
from flask import Flask, request
from typing import Dict

app = Flask(__name__)

# الإعدادات من متغيرات Railway
CONFIG = {
    'tg_token': os.getenv('TG_BOT_TOKEN',"8424629993:AAFUwn5SAkq78wGML9WRt5KSr9o9aJ_thCs"),
    'vt_key': os.getenv('VT_API_KEY',"0017f41ba8d15d3721c762f29d2c359d33101a570b41fd651dac1cd78343335c"),
    'openai_key': os.getenv('OPENAI_KEY',"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")
}

class TelegramScanner:
    def __init__(self):
        self.api = f"https://api.telegram.org/bot{CONFIG['tg_token']}"
    
    def send_msg(self, chat_id: int, text: str, reply_to=None):
        """إرسال رسالة"""
        try:
            payload = {
                'chat_id': chat_id,
                'text': text[:4000],
                'parse_mode': 'HTML',
                'disable_web_page_preview': True
            }
            if reply_to:
                payload['reply_to_message_id'] = reply_to
            
            requests.post(f"{self.api}/sendMessage", json=payload, timeout=10)
        except:
            pass
    
    def send_doc(self, chat_id: int, doc_path: str, caption: str = ""):
        """إرسال ملف"""
        try:
            with open(doc_path, 'rb') as f:
                requests.post(
                    f"{self.api}/sendDocument",
                    data={'chat_id': chat_id, 'caption': caption[:1024]},
                    files={'document': f},
                    timeout=30
                )
        except:
            pass

    def get_file(self, file_id: str) -> bytes:
        """تحميل ملف من تلغرام"""
        try:
            # الحصول على رابط التحميل
            r = requests.get(f"{self.api}/getFile?file_id={file_id}", timeout=10)
            file_path = r.json()['result']['file_path']
            
            # تحميل الملف
            file_url = f"https://api.telegram.org/file/bot{CONFIG['tg_token']}/{file_path}"
            r = requests.get(file_url, timeout=30)
            return r.content
        except:
            return b''

    def get_hashes(self, data: bytes) -> Dict:
        """حساب الهاشات"""
        return {
            'md5': hashlib.md5(data).hexdigest(),
            'sha1': hashlib.sha1(data).hexdigest(),
            'sha256': hashlib.sha256(data).hexdigest()
        }

    def vt_check(self, file_hash: str) -> Dict:
        """فحص VirusTotal"""
        if not CONFIG['vt_key']:
            return {'error': 'VT not configured'}
        try:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers={"x-apikey": CONFIG['vt_key']},
                timeout=10
            )
            if r.status_code == 200:
                d = r.json()['data']['attributes']
                s = d.get('last_analysis_stats', {})
                return {
                    'found': True,
                    'detection': f"{s.get('malicious',0)}/{sum(s.values())}",
                    'malicious': s.get('malicious', 0),
                    'suspicious': s.get('suspicious', 0),
                    'type': d.get('type_description', 'Unknown'),
                    'names': d.get('names', [])[:3]
                }
            return {'found': False}
        except Exception as e:
            return {'error': str(e)}

    def extract_iocs(self, data: bytes) -> Dict:
        """استخراج مؤشرات الاختراق"""
        text = data.decode('utf-8', errors='ignore')
        return {
            'urls': list(set(re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', text)))[:5],
            'ips': list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)))[:5],
            'emails': list(set(re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', text)))[:3]
        }

    def ai_analyze(self, info: Dict) -> str:
        """تحليل ذكي"""
        if not CONFIG['openai_key']:
            return "AI: Not configured"
        
        prompt = f"""Analyze malware quickly:
File: {info['name']} ({info['size']} bytes)
VT: {info['vt'].get('detection', 'N/A')}
IOCs: {len(info['iocs']['urls'])} URLs, {len(info['iocs']['ips'])} IPs

Give: 1) Threat Level 1-10 2) Type 3) 2 key behaviors 4) Advice"""

        try:
            r = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {CONFIG['openai_key']}"},
                json={
                    "model": "gpt-3.5-turbo",
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 250
                },
                timeout=15
            )
            return r.json()['choices'][0]['message']['content']
        except:
            return "AI: Analysis failed"

    def scan_file(self, file_data: bytes, filename: str, chat_id: int, msg_id: int):
        """فحص كامل وإرسال النتيجة"""
        # إشعار البدء
        self.send_msg(chat_id, "🔍 جاري فحص الملف...", msg_id)
        
        # الهاشات
        hashes = self.get_hashes(file_data)
        
        # VirusTotal
        vt = self.vt_check(hashes['sha256'])
        
        # IOCs
        iocs = self.extract_iocs(file_data)
        
        # تجميع المعلومات
        info = {
            'name': filename,
            'size': len(file_data),
            'hashes': hashes,
            'vt': vt,
            'iocs': iocs
        }
        
        # تحليل ذكي
        ai_report = self.ai_analyze(info)
        info['ai'] = ai_report
        
        # تحديد مستوى الخطورة
        threat_level = "🟢 منخفض"
        if vt.get('malicious', 0) > 10:
            threat_level = "🔴 عالي"
        elif vt.get('malicious', 0) > 0:
            threat_level = "🟠 متوسط"
        elif len(iocs['urls']) > 0:
            threat_level = "🟡 مشبوه"
        
        # بناء التقرير
        report = f"""🛡️ <b>نتيجة الفحص</b>

📁 <b>{filename}</b>
💾 الحجم: {len(file_data):,} بايت
⚠️ الخطورة: {threat_level}

🔐 <b>الهاشات:</b>
<code>MD5: {hashes['md5']}
SHA1: {hashes['sha1']}
SHA256: {hashes['sha256']}</code>

🔍 <b>VirusTotal:</b>"""
        
        if vt.get('found'):
            report += f"""
• الكشف: <b>{vt['detection']}</b>
• النوع: {vt.get('type', 'Unknown')}
• أسماء سابقة: {', '.join(vt.get('names', []))}"""
        else:
            report += "\n• غير موجود في القاعدة"
        
        report += f"""

🔗 <b>مؤشرات الاختراق:</b>
• URLs: {len(iocs['urls'])}
• IPs: {len(iocs['ips'])}
• Emails: {len(iocs['emails'])}"""
        
        if iocs['urls']:
            report += f"\n\n<b>روابط مشبوهة:</b>\n" + '\n'.join(iocs['urls'][:3])
        
        report += f"""

🤖 <b>التحليل الذكي:</b>
{ai_report}"""
        
        # إرسال التقرير
        self.send_msg(chat_id, report, msg_id)
        
        # حفظ تقرير نصي مرفق
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                json.dump(info, f, indent=2, default=str)
                f.write("\n\n=== REPORT ===\n")
                f.write(report)
                temp_path = f.name
            
            self.send_doc(chat_id, temp_path, "📎 تقرير مفصل JSON")
            os.unlink(temp_path)
        except:
            pass


# إنشاء البوت
bot = TelegramScanner()

@app.route('/')
def home():
    return "✅ Telegram Malware Bot is running"

@app.route('/webhook', methods=['POST'])
def webhook():
    """استقبال تحديثات تلغرام"""
    data = request.get_json()
    
    if not data or 'message' not in data:
        return 'OK', 200
    
    msg = data['message']
    chat_id = msg['chat']['id']
    msg_id = msg['message_id']
    
    # التعامل مع الأوامر
    if 'text' in msg:
        text = msg['text']
        
        if text == '/start':
            bot.send_msg(chat_id, 
                "👋 مرحباً! أنا بوت فحص الملفات الخبيثة.\n\n"
                "📤 أرسل لي أي ملف (exe, dll, pdf, doc, إلخ) وسأفحصه لك.\n\n"
                "🔍 ما يقوم به البوت:\n"
                "• حساب الهاشات (MD5, SHA1, SHA256)\n"
                "• فحص VirusTotal\n"
                "• استخراج الروابط والـ IPs\n"
                "• تحليل ذكي بالـ AI\n\n"
                "⚠️ <b>تحذير:</b> لا ترسل ملفات حساسة أو شخصية!",
                msg_id
            )
            return 'OK', 200
        
        elif text == '/help':
            bot.send_msg(chat_id,
                "📋 <b>الأوامر المتاحة:</b>\n\n"
                "/start - بدء البوت\n"
                "/help - المساعدة\n\n"
                "فقط أرسل الملف مباشرة!",
                msg_id
            )
            return 'OK', 200
    
    # التعامل مع الملفات
    file_info = None
    filename = "unknown"
    
    if 'document' in msg:
        file_info = msg['document']
        filename = file_info.get('file_name', 'document')
    elif 'video' in msg:
        file_info = msg['video']
        filename = 'video.mp4'
    elif 'audio' in msg:
        file_info = msg['audio']
        filename = 'audio.mp3'
    elif 'photo' in msg:
        # الصور - آخر حجم (الأفضل جودة)
        file_info = msg['photo'][-1]
        filename = 'photo.jpg'
    
    if file_info:
        # التحقق من الحجم (50MB max)
        file_size = file_info.get('file_size', 0)
        if file_size > 50 * 1024 * 1024:
            bot.send_msg(chat_id, "❌ الملف كبير جداً (الحد الأقصى 50MB)", msg_id)
            return 'OK', 200
        
        # تحميل وفحص
        file_data = bot.get_file(file_info['file_id'])
        if file_data:
            bot.scan_file(file_data, filename, chat_id, msg_id)
        else:
            bot.send_msg(chat_id, "❌ فشل تحميل الملف", msg_id)
    
    return 'OK', 200

@app.route('/set-webhook')
def set_webhook():
    """إعداد الـ Webhook (شغل مرة واحدة)"""
    webhook_url = f"https://{request.host}/webhook"
    r = requests.get(
        f"https://api.telegram.org/bot{CONFIG['tg_token']}/setWebhook",
        params={'url': webhook_url},
        timeout=10
    )
    return r.json()

if __name__ == '__main__':
    port = int(os.getenv('PORT', 3000))
    app.run(host='0.0.0.0', port=port)
