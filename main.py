#!/usr/bin/env python3
"""
نظام فحص خفيف لـ Railway
Lightweight Malware Scanner for Railway
"""

import hashlib, json, requests, re, os, tempfile
from typing import Dict, List
from flask import Flask, request, jsonify

app = Flask(__name__)

# الإعدادات من متغيرات البيئة (Railway Variables)
CONFIG = {
    'vt_key': os.getenv('VT_API_KEY', '0017f41ba8d15d3721c762f29d2c359d33101a570b41fd651dac1cd78343335c'),
    'ollama': os.getenv('OLLAMA_URL', 'https://ollama.com'),  # أو استخدم OpenAI API
    'tg_token': os.getenv('TG_BOT_TOKEN', '8424629993:AAFUwn5SAkq78wGML9WRt5KSr9o9aJ_thCs'),
    'tg_chat': os.getenv('TG_CHAT_ID', '8463431328'),
    'openai_key': os.getenv('OPENAI_KEY', '')  # بديل لـ Ollama
}

class CloudScanner:
    def get_hashes(self, content: bytes) -> Dict:
        """حساب هاشات من المحتوى مباشرة"""
        return {
            'md5': hashlib.md5(content).hexdigest(),
            'sha1': hashlib.sha1(content).hexdigest(),
            'sha256': hashlib.sha256(content).hexdigest()
        }

    def vt_check(self, file_hash: str) -> Dict:
        """فحص VirusTotal"""
        if not CONFIG['vt_key']:
            return {'error': 'No VT key'}
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
                    'type': d.get('type_description', 'Unknown')
                }
            return {'found': False}
        except Exception as e:
            return {'error': str(e)}

    def extract_iocs(self, content: bytes) -> Dict:
        """استخراج مؤشرات الاختراق"""
        text = content.decode('utf-8', errors='ignore')
        return {
            'urls': list(set(re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', text)))[:10],
            'ips': list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)))[:10],
            'domains': list(set(re.findall(r'\b[a-zA-Z0-9-]+\.(com|net|org|ru|cn|io)\b', text)))[:10]
        }

    def ai_report(self, data: Dict) -> str:
        """تحليل ذكي باستخدام OpenAI (أفضل لـ Railway)"""
        if not CONFIG['openai_key']:
            return "AI analysis disabled"
        
        prompt = f"""Analyze this malware sample briefly:
- File: {data['file']}
- Size: {data['size']} bytes
- VT Detection: {data['vt'].get('detection', 'N/A')}
- IOCs: {len(data['iocs']['urls'])} URLs, {len(data['iocs']['ips'])} IPs

Provide: Threat Level (1-10), Malware Type, Key Behavior, Recommendations."""

        try:
            r = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {CONFIG['openai_key']}"},
                json={
                    "model": "gpt-3.5-turbo",
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 300
                },
                timeout=15
            )
            return r.json()['choices'][0]['message']['content']
        except:
            return "AI analysis failed"

    def telegram(self, msg: str):
        """إشعار Telegram"""
        if not (CONFIG['tg_token'] and CONFIG['tg_chat']):
            return
        try:
            requests.post(
                f"https://api.telegram.org/bot{CONFIG['tg_token']}/sendMessage",
                data={
                    'chat_id': CONFIG['tg_chat'],
                    'text': msg[:4000],
                    'parse_mode': 'HTML'
                },
                timeout=10
            )
        except:
            pass

    def scan(self, file_content: bytes, filename: str) -> Dict:
        """فحص كامل"""
        # الهاشات
        hashes = self.get_hashes(file_content)
        
        # VT
        vt = self.vt_check(hashes['sha256'])
        
        # IOCs
        iocs = self.extract_iocs(file_content)
        
        # تجميع
        data = {
            'file': filename,
            'size': len(file_content),
            'hashes': hashes,
            'vt': vt,
            'iocs': iocs
        }
        
        # AI
        data['report'] = self.ai_report(data)
        
        # إشعار
        msg = f"""🛡️ <b>Malware Scan</b>
📁 {filename} ({len(file_content):,} bytes)

<code>MD5: {hashes['md5']}
SHA256: {hashes['sha256'][:32]}...</code>

🔍 VT: {vt.get('detection', 'N/A')}
🔗 IOCs: {len(iocs['urls'])} URLs | {len(iocs['ips'])} IPs

🤖 <b>Analysis:</b>
{data['report'][:500]}"""
        
        self.telegram(msg)
        return data


scanner = CloudScanner()

@app.route('/')
def home():
    return "✅ Malware Scanner API is running"

@app.route('/scan', methods=['POST'])
def scan_file():
    """استقبال ملف للفحص"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Empty filename'}), 400
    
    try:
        content = file.read()
        if len(content) > 50 * 1024 * 1024:  # 50MB max
            return jsonify({'error': 'File too large (max 50MB)'}), 413
        
        result = scanner.scan(content, file.filename)
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/scan-hash/<file_hash>')
def scan_hash(file_hash):
    """فحص بهاش فقط (بدون رفع ملف)"""
    vt = scanner.vt_check(file_hash)
    return jsonify({
        'hash': file_hash,
        'virustotal': vt
    })

if __name__ == '__main__':
    port = int(os.getenv('PORT', 3000))
    app.run(host='0.0.0.0', port=port)
