import re
import subprocess
import asyncio
import tempfile
import os
from typing import List
from pathlib import Path

class StringsExtractor:
    def __init__(self):
        self.min_length = 4
    
    def extract_strings(self, file_path: str) -> List[str]:
        """استخراج النصوص القابلة للطباعة من الملف"""
        strings = []
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # استخراج ASCII
            ascii_strings = re.findall(rb'[\x20-\x7E]{' + str(self.min_length).encode() + rb',}', content)
            strings.extend([s.decode('ascii', errors='ignore') for s in ascii_strings])
            
            # استخراج Unicode (UTF-16LE)
            unicode_pattern = rb'(?:[\x20-\x7E]\x00){' + str(self.min_length).encode() + rb',}'
            unicode_matches = re.findall(unicode_pattern, content)
            strings.extend([s.decode('utf-16le', errors='ignore') for s in unicode_matches])
            
            # إزالة التكرارات والفرز حسب الطول
            unique_strings = list(set(strings))
            unique_strings.sort(key=len, reverse=True)
            
            # إرجاع أهم 100 نص فقط لتجنب الازدحام
            return unique_strings[:100]
            
        except Exception as e:
            return [f"Error extracting strings: {str(e)}"]
    
    async def extract_floss(self, file_path: str) -> List[str]:
        """استخراج النصوص المشوهة باستخدام FLOSS (محاكاة)"""
        # ملاحظة: FLOSS يتطلب تثبيت منفصل، هنا نستخدم محاكاة
        # في الإنتاج، يمكن استخدام subprocess مع floss المثبت
        
        floss_results = []
        
        try:
            # محاولة تشغيل floss إذا كان مثبتاً
            process = await asyncio.create_subprocess_exec(
                'floss', file_path, '--no-static-strings', '--quiet',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=60
            )
            
            if process.returncode == 0:
                decoded_strings = stdout.decode('utf-8', errors='ignore').split('\n')
                floss_results = [s.strip() for s in decoded_strings if len(s.strip()) > 4][:50]
            else:
                floss_results = ["FLOSS analysis completed with warnings"]
                
        except FileNotFoundError:
            # إذا لم يكن FLOSS مثبتاً، نستخدم تحليل بديل
            floss_results = await self._emulate_floss(file_path)
        except asyncio.TimeoutError:
            floss_results = ["FLOSS analysis timed out"]
        except Exception as e:
            floss_results = [f"FLOSS analysis error: {str(e)}"]
        
        return floss_results
    
    async def _emulate_floss(self, file_path: str) -> List[str]:
        """محاكاة FLOSS باستخدام تقنيات استخراج متقدمة"""
        # تحليل بديل للنصوص المشوهة
        results = []
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # البحث عن أنماط Base64
            b64_pattern = rb'[A-Za-z0-9+\/]{50,}={0,2}'
            b64_matches = re.findall(b64_pattern, content)
            
            for match in b64_matches[:10]:
                try:
                    import base64
                    decoded = base64.b64decode(match)
                    # التحقق إذا كان فك التشفير ناجحاً
                    if all(32 <= b <= 126 for b in decoded[:20]):
                        results.append(f"Possible Base64: {decoded.decode('ascii', errors='ignore')[:100]}")
                except:
                    pass
            
            # البحث عن أنماط XOR شائعة
            xor_keys = [0x01, 0x10, 0x13, 0x20, 0x41, 0x50, 0x55, 0xAA, 0xFF]
            for key in xor_keys[:3]:  # فحص أول 3 مفاتيح فقط للسرعة
                decoded = bytes([b ^ key for b in content[:1000]])
                ascii_parts = re.findall(rb'[\x20-\x7E]{6,}', decoded)
                if ascii_parts:
                    results.append(f"XOR key 0x{key:02X} found: {ascii_parts[0].decode('ascii', errors='ignore')[:50]}")
            
            if not results:
                results.append("No obfuscated strings detected (FLOSS not installed, using fallback)")
                
        except Exception as e:
            results.append(f"Fallback analysis error: {str(e)}")
        
        return results[:20]