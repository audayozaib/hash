# نظام الفحص المؤتمت للبرامج الخبيثة
# Automated Malware Analysis System

import hashlib
import os
import json
import requests
import subprocess
import tempfile
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import logging

# إعداد التسجيل
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('malware_scanner.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class MalwareAnalyzer:
    def __init__(self, config: Dict):
        """
        تهيئة المحلل مع الإعدادات
        
        Args:
            config: قاموس يحتوي على:
                - virustotal_api_key: مفتاح VirusTotal API
                - ollama_host: عنوان Ollama (مثال: http://localhost:11434)
                - ollama_model: نموذج Ollama (مثال: llama3, mistral)
                - telegram_bot_token: توكن بوت Telegram
                - telegram_chat_id: معرف المحادثة في Telegram
                - yara_rules_path: مسار قواعد YARA
        """
        self.config = config
        self.results = {}
        
    def calculate_hashes(self, file_path: str) -> Dict[str, str]:
        """حساب الهاشات MD5, SHA1, SHA256 للملف"""
        logger.info(f"جاري حساب الهاشات للملف: {file_path}")
        
        hashes = {}
        algorithms = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256()
        }
        
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    for algo in algorithms.values():
                        algo.update(chunk)
            
            for name, algo in algorithms.items():
                hashes[name] = algo.hexdigest()
                
            logger.info(f"تم حساب الهاشات: SHA256={hashes['sha256'][:16]}...")
            return hashes
            
        except Exception as e:
            logger.error(f"خطأ في حساب الهاشات: {e}")
            raise

    def check_virustotal(self, file_hash: str) -> Dict:
        """التحقق من الهاش في VirusTotal"""
        logger.info(f"جاري التحقق من VirusTotal للهاش: {file_hash[:16]}...")
        
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {
            "x-apikey": self.config['virustotal_api_key'],
            "Accept": "application/json"
        }
        
        try:
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                
                last_analysis = attributes.get('last_analysis_stats', {})
                detection_ratio = f"{last_analysis.get('malicious', 0)}/{sum(last_analysis.values())}"
                
                result = {
                    'found': True,
                    'detection_ratio': detection_ratio,
                    'malicious_count': last_analysis.get('malicious', 0),
                    'suspicious_count': last_analysis.get('suspicious', 0),
                    'harmless_count': last_analysis.get('harmless', 0),
                    'undetected_count': last_analysis.get('undetected', 0),
                    'names': attributes.get('names', [])[:5],  # أول 5 أسماء
                    'type_description': attributes.get('type_description', 'Unknown'),
                    'first_seen': attributes.get('first_submission_date', 'Unknown'),
                    'last_analysis': attributes.get('last_analysis_date', 'Unknown'),
                    'tags': attributes.get('tags', []),
                    'reputation': attributes.get('reputation', 0),
                    'sandbox_verdicts': list(attributes.get('sandbox_verdicts', {}).keys())[:3]
                }
                
                logger.info(f"VirusTotal: {detection_ratio} مكشوف")
                return result
                
            elif response.status_code == 404:
                logger.info("الملف غير موجود في VirusTotal")
                return {'found': False, 'message': 'File not found in VirusTotal database'}
            else:
                logger.error(f"خطأ في VirusTotal: {response.status_code}")
                return {'found': False, 'error': f'HTTP {response.status_code}'}
                
        except Exception as e:
            logger.error(f"خطأ في الاتصال بـ VirusTotal: {e}")
            return {'found': False, 'error': str(e)}

    def yara_scan(self, file_path: str) -> List[Dict]:
        """فحص الملف باستخدام YARA"""
        logger.info("جاري الفحص بـ YARA...")
        
        if not os.path.exists(self.config.get('yara_rules_path', '')):
            logger.warning("مسار قواعد YARA غير موجود")
            return [{'error': 'YARA rules path not configured'}]
        
        try:
            import yara
            rules = yara.compile(filepath=self.config['yara_rules_path'])
            matches = rules.match(file_path)
            
            results = []
            for match in matches:
                result = {
                    'rule_name': match.rule,
                    'namespace': match.namespace,
                    'tags': list(match.tags),
                    'meta': dict(match.meta),
                    'strings': []
                }
                
                # استخراج النصوص المطابقة
                for string_match in match.strings:
                    for instance in string_match.instances:
                        result['strings'].append({
                            'identifier': string_match.identifier,
                            'offset': instance.offset,
                            'matched_data': instance.matched_data[:50].hex() if instance.matched_data else ''
                        })
                
                results.append(result)
            
            logger.info(f"تم العثور على {len(results)} قواعد مطابقة")
            return results
            
        except ImportError:
            logger.error("مكتبة yara-python غير مثبتة")
            return [{'error': 'yara-python not installed'}]
        except Exception as e:
            logger.error(f"خطأ في فحص YARA: {e}")
            return [{'error': str(e)}]

    def extract_strings(self, file_path: str, min_length: int = 4) -> Dict[str, List[str]]:
        """استخراج النصوص من الملف"""
        logger.info("جاري استخراج النصوص...")
        
        strings_result = {
            'ascii': [],
            'unicode': [],
            'suspicious': [],
            'urls': [],
            'ips': [],
            'emails': [],
            'registry_keys': []
        }
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # استخراج ASCII strings
            ascii_strings = []
            current = []
            for byte in content:
                if 32 <= byte <= 126:
                    current.append(chr(byte))
                else:
                    if len(current) >= min_length:
                        ascii_strings.append(''.join(current))
                    current = []
            
            strings_result['ascii'] = ascii_strings[:100]  # أول 100 نص
            
            # استخراج Unicode strings (UTF-16LE)
            unicode_strings = []
            try:
                decoded = content.decode('utf-16le', errors='ignore')
                import re
                unicode_strings = re.findall(r'[\x20-\x7E]{4,}', decoded)[:50]
            except:
                pass
            
            strings_result['unicode'] = unicode_strings
            
            # تحليل النصوص المشبوهة
            import re
            all_strings = ascii_strings + unicode_strings
            
            for s in all_strings:
                # البحث عن URLs
                if re.match(r'https?://[^\s]+', s):
                    strings_result['urls'].append(s)
                # البحث عن IPs
                elif re.match(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', s):
                    strings_result['ips'].append(s)
                # البحث عن Emails
                elif re.match(r'[\w\.-]+@[\w\.-]+\.\w+', s):
                    strings_result['emails'].append(s)
                # البحث عن مفاتيح الريجستري
                elif 'HKEY_' in s or 'SOFTWARE\\' in s:
                    strings_result['registry_keys'].append(s)
                # كلمات مشبوهة
                elif any(keyword in s.lower() for keyword in 
                        ['cmd.exe', 'powershell', 'regsvr32', 'rundll32', 
                         'CreateRemoteThread', 'VirtualAlloc', 'WinExec',
                         'CreateProcess', 'socket', 'connect', 'download']):
                    strings_result['suspicious'].append(s)
            
            logger.info(f"تم استخراج {len(ascii_strings)} نص ASCII")
            return strings_result
            
        except Exception as e:
            logger.error(f"خطأ في استخراج النصوص: {e}")
            return {'error': str(e)}

    def extract_floss(self, file_path: str) -> List[str]:
        """استخراج النصوص المشوهة باستخدام FLOSS"""
        logger.info("جاري استخراج النصوص المشوهة بـ FLOSS...")
        
        floss_results = []
        
        try:
            # التحقق من وجود FLOSS
            result = subprocess.run(
                ['floss', '--version'], 
                capture_output=True, 
                text=True, 
                timeout=5
            )
            
            if result.returncode != 0:
                return ['FLOSS not installed properly']
            
            # تشغيل FLOSS
            cmd = [
                'floss',
                '-n', '6',  # minimum string length
                '--no-static-strings',  # تجنب التكرار مع strings العادي
                file_path
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                # تصفية النتائج
                decoded_strings = []
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith('#') and len(line) > 4:
                        decoded_strings.append(line)
                
                floss_results = decoded_strings[:50]  # أول 50 نتيجة
                logger.info(f"تم استخراج {len(floss_results)} نص مشوه")
            else:
                floss_results = [f"FLOSS error: {result.stderr}"]
                
        except FileNotFoundError:
            logger.warning("FLOSS غير مثبت على النظام")
            floss_results = ['FLOSS not installed - install from: https://github.com/mandiant/flare-floss']
        except subprocess.TimeoutExpired:
            logger.error("انتهى وقت تشغيل FLOSS")
            floss_results = ['FLOSS timeout']
        except Exception as e:
            logger.error(f"خطأ في تشغيل FLOSS: {e}")
            floss_results = [f'Error: {str(e)}']
        
        return floss_results

    def analyze_with_ollama(self, analysis_data: Dict) -> str:
        """إرسال النتائج إلى Ollama لإنشاء تقرير"""
        logger.info("جاري إنشاء التقرير الذكي باستخدام Ollama...")
        
        # تجهيز البيانات للإرسال
        prompt = self._create_analysis_prompt(analysis_data)
        
        try:
            response = requests.post(
                f"{self.config['ollama_host']}/api/generate",
                json={
                    "model": self.config['ollama_model'],
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.3,
                        "num_predict": 2000
                    }
                },
                timeout=120
            )
            
            if response.status_code == 200:
                result = response.json()
                report = result.get('response', '')
                logger.info("تم إنشاء التقرير بنجاح")
                return report
            else:
                error_msg = f"خطأ في Ollama: {response.status_code}"
                logger.error(error_msg)
                return error_msg
                
        except Exception as e:
            error_msg = f"خطأ في الاتصال بـ Ollama: {e}"
            logger.error(error_msg)
            return error_msg

    def _create_analysis_prompt(self, data: Dict) -> str:
        """إنشاء prompt للتحليل الذكي"""
        
        vt_data = data.get('virustotal', {})
        yara_matches = data.get('yara', [])
        strings = data.get('strings', {})
        floss = data.get('floss', [])
        file_info = data.get('file_info', {})
        
        prompt = f"""أنت محلل برمجيات خبيثة متخصص. قم بتحليل البيانات التالية وإنشاء تقرير احترافي باللغة العربية:

📁 معلومات الملف:
- الاسم: {file_info.get('name', 'Unknown')}
- الحجم: {file_info.get('size', 0)} بايت
- النوع: {file_info.get('type', 'Unknown')}
- MD5: {file_info.get('md5', 'N/A')}
- SHA1: {file_info.get('sha1', 'N/A')}
- SHA256: {file_info.get('sha256', 'N/A')}

🔍 نتائج VirusTotal:
"""
        
        if vt_data.get('found'):
            prompt += f"""- نسبة الكشف: {vt_data.get('detection_ratio', 'N/A')}
- عدد المحركات الخبيثة: {vt_data.get('malicious_count', 0)}
- عدد المحركات المشبوهة: {vt_data.get('suspicious_count', 0)}
- الوصف: {vt_data.get('type_description', 'Unknown')}
- الأسماء السابقة: {', '.join(vt_data.get('names', [])[:3])}
- العلامات: {', '.join(vt_data.get('tags', [])[:5])}
"""
        else:
            prompt += "- الملف غير موجود في قاعدة بيانات VirusTotal\n"

        prompt += f"\n🛡️ نتائج YARA: {len(yara_matches)} قواعد مطابقة\n"
        if yara_matches and not any('error' in str(m) for m in yara_matches):
            for match in yara_matches[:5]:
                prompt += f"- {match.get('rule_name', 'Unknown')}: {match.get('meta', {}).get('description', 'No description')}\n"

        prompt += f"\n📝 النصوص المستخرجة:\n"
        prompt += f"- عدد URLs: {len(strings.get('urls', []))}\n"
        prompt += f"- عدد IPs: {len(strings.get('ips', []))}\n"
        prompt += f"- عدد Emails: {len(strings.get('emails', []))}\n"
        prompt += f"- عدد مفاتيح الريجستري: {len(strings.get('registry_keys', []))}\n"
        prompt += f"- عدد النصوص المشبوهة: {len(strings.get('suspicious', []))}\n"
        prompt += f"- عدد النصوص المشوهة (FLOSS): {len(floss)}\n"

        if strings.get('urls'):
            prompt += f"\n🔗 URLs مشبوهة: {', '.join(strings['urls'][:3])}\n"
        if strings.get('ips'):
            prompt += f"🌐 IPs مشبوهة: {', '.join(strings['ips'][:3])}\n"

        prompt += """
المطلوب:
1. تقييم مستوى الخطورة (منخفض/متوسط/عالي/حرج)
2. نوع البرمجية الخبيثة المحتمل (رانسوموير، تروجان، باك دور، إلخ)
3. سلوكيات مشبوهة محتملة
4. مؤشرات الاختراق (IOCs)
5. توصيات للتعامل مع الملف
6. ملخص تنفيذي

اكتب التقرير بشكل منظم ومهني."""
        
        return prompt

    def send_to_telegram(self, message: str, file_path: Optional[str] = None) -> bool:
        """إرسال النتائج إلى Telegram"""
        logger.info("جاري إرسال التقرير إلى Telegram...")
        
        bot_token = self.config['telegram_bot_token']
        chat_id = self.config['telegram_chat_id']
        
        try:
            # إرسال الرسالة النصية
            url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            
            # تقسيم الرسالة إذا كانت طويلة
            max_length = 4000
            if len(message) > max_length:
                parts = [message[i:i+max_length] for i in range(0, len(message), max_length)]
            else:
                parts = [message]
            
            for i, part in enumerate(parts):
                payload = {
                    'chat_id': chat_id,
                    'text': f"📊 تقرير الفحص ({i+1}/{len(parts)}):\n\n{part}",
                    'parse_mode': 'HTML'
                }
                
                response = requests.post(url, data=payload, timeout=30)
                
                if response.status_code != 200:
                    logger.error(f"خطأ في إرسال Telegram: {response.text}")
                    return False
            
            # إرسال الملف الأصلي إذا كان مطلوباً (بحذر!)
            # ملاحظة: في البيئة الإنتاجية، يجب التأكد من أن الملف آمن قبل إرساله
            if file_path and os.path.exists(file_path) and os.path.getsize(file_path) < 10*1024*1024:  # أقل من 10MB
                doc_url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
                with open(file_path, 'rb') as f:
                    files = {'document': f}
                    data = {'chat_id': chat_id, 'caption': '📎 الملف المحلل'}
                    response = requests.post(doc_url, data=data, files=files, timeout=60)
            
            logger.info("تم إرسال التقرير إلى Telegram بنجاح")
            return True
            
        except Exception as e:
            logger.error(f"خطأ في إرسال Telegram: {e}")
            return False

    def analyze_file(self, file_path: str) -> Dict:
        """تشغيل تحليل كامل للملف"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"الملف غير موجود: {file_path}")
        
        logger.info(f"=== بدء تحليل الملف: {file_path} ===")
        start_time = datetime.now()
        
        # جمع المعلومات الأساسية
        file_stat = os.stat(file_path)
        file_info = {
            'name': os.path.basename(file_path),
            'path': file_path,
            'size': file_stat.st_size,
            'type': 'PE/Executable' if file_path.endswith(('.exe', '.dll')) else 'Unknown',
            'created': datetime.fromtimestamp(file_stat.st_ctime).isoformat(),
            'modified': datetime.fromtimestamp(file_stat.st_mtime).isoformat()
        }
        
        # 1. حساب الهاشات
        hashes = self.calculate_hashes(file_path)
        file_info.update(hashes)
        
        # 2. فحص VirusTotal
        vt_result = self.check_virustotal(hashes['sha256'])
        
        # 3. فحص YARA
        yara_result = self.yara_scan(file_path)
        
        # 4. استخراج النصوص
        strings_result = self.extract_strings(file_path)
        
        # 5. استخراج النصوص المشوهة
        floss_result = self.extract_floss(file_path)
        
        # تجميع النتائج
        analysis_data = {
            'file_info': file_info,
            'virustotal': vt_result,
            'yara': yara_result,
            'strings': strings_result,
            'floss': floss_result,
            'scan_time': datetime.now().isoformat()
        }
        
        # 6. إنشاء تقرير ذكي
        ai_report = self.analyze_with_ollama(analysis_data)
        analysis_data['ai_report'] = ai_report
        
        # 7. إرسال إلى Telegram
        full_report = self._format_full_report(analysis_data)
        self.send_to_telegram(full_report, file_path)
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        logger.info(f"=== اكتمل التحليل في {duration:.2f} ثانية ===")
        
        return analysis_data

    def _format_full_report(self, data: Dict) -> str:
        """تنسيق التقرير الكامل للإرسال"""
        info = data['file_info']
        vt = data['virustotal']
        
        report = f"""🛡️ <b>تقرير الفحص الأمني المتقدم</b>

📁 <b>معلومات الملف:</b>
• الاسم: <code>{info['name']}</code>
• الحجم: {info['size']:,} بايت ({info['size']/1024:.2f} KB)
• النوع: {info['type']}
• تاريخ الفحص: {data['scan_time']}

🔐 <b>الهاشات:</b>
• MD5: <code>{info['md5']}</code>
• SHA1: <code>{info['sha1']}</code>
• SHA256: <code>{info['sha256']}</code>

"""
        
        if vt.get('found'):
            report += f"""🔍 <b>نتائج VirusTotal:</b>
• نسبة الكشف: <b>{vt['detection_ratio']}</b>
• الخبيثة: {vt['malicious_count']} | المشبوهة: {vt['suspicious_count']} | الآمنة: {vt['harmless_count']}
• الوصف: {vt['type_description']}
"""
            if vt.get('tags'):
                report += f"• العلامات: {', '.join(vt['tags'][:5])}\n"
        else:
            report += "🔍 <b>VirusTotal:</b> غير موجود في القاعدة\n"

        report += f"\n🛡️ <b>YARA:</b> {len(data['yara'])} قواعد مطابقة\n"
        
        strings = data['strings']
        report += f"""
📝 <b>النصوص المستخرجة:</b>
• URLs: {len(strings.get('urls', []))}
• IPs: {len(strings.get('ips', []))}
• Emails: {len(strings.get('emails', []))}
• مفاتيح ريجستري: {len(strings.get('registry_keys', []))}
• نصوص FLOSS: {len(data['floss'])}

🤖 <b>التحليل الذكي:</b>
{data.get('ai_report', 'غير متوفر')}
"""
        
        return report


# مثال على الاستخدام
if __name__ == "__main__":
    # إعدادات النظام (يجب تعديلها حسب بيئتك)
    CONFIG = {
        'virustotal_api_key': '0017f41ba8d15d3721c762f29d2c359d33101a570b41fd651dac1cd78343335c',
        'ollama_host': 'http://localhost:11434',
        'ollama_model': 'llama3',  # أو 'mistral', 'codellama', إلخ
        'telegram_bot_token': '8424629993:AAFUwn5SAkq78wGML9WRt5KSr9o9aJ_thCs',
        'telegram_chat_id': '8463431328',
        'yara_rules_path': './rules/malware_rules.yar'  # اختياري
    }
    
    # إنشاء المحلل
    analyzer = MalwareAnalyzer(CONFIG)
