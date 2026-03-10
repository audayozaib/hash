import yara
import os
from typing import List, Dict, Any
from pathlib import Path

class YaraEngine:
    def __init__(self):
        self.rules_path = "rules/malware_rules.yar"
        self.rules = self._load_rules()
    
    def _load_rules(self):
        """تحميل قواعد YARA"""
        # إنشاء قواعد افتراضية إذا لم تكن موجودة
        if not os.path.exists(self.rules_path):
            self._create_default_rules()
        
        try:
            return yara.compile(filepath=self.rules_path)
        except Exception as e:
            print(f"Error loading YARA rules: {e}")
            return None
    
    def _create_default_rules(self):
        """إنشاء قواعد YARA افتراضية"""
        os.makedirs("rules", exist_ok=True)
        
        default_rules = '''
rule Suspicious_PE_Imports {
    meta:
        description = "Detects suspicious imports in PE files"
        author = "MalwareScanner"
    strings:
        $kernel32 = "kernel32.dll" nocase
        $virtualalloc = "VirtualAlloc" nocase
        $virtualprotect = "VirtualProtect" nocase
        $createremotethread = "CreateRemoteThread" nocase
        $writefile = "WriteFile" nocase
        $winexec = "WinExec" nocase
        $createprocess = "CreateProcess" nocase
        $loadlibrary = "LoadLibrary" nocase
        $getprocaddress = "GetProcAddress" nocase
        $internetopen = "InternetOpen" nocase
        $urldownload = "URLDownloadToFile" nocase
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule Base64_Encoded_Binary {
    meta:
        description = "Detects Base64 encoded binary data"
    strings:
        $b64_pattern = /[A-Za-z0-9+\/]{100,}={0,2}/
    condition:
        #b64_pattern > 5
}

rule Suspicious_Strings {
    meta:
        description = "Detects suspicious strings commonly found in malware"
    strings:
        $cmd1 = "cmd.exe" nocase
        $cmd2 = "powershell" nocase
        $cmd3 = "-ep bypass" nocase
        $cmd4 = "-enc" nocase
        $cmd5 = "IEX" nocase
        $cmd6 = "Invoke-Expression" nocase
        $registry = "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" nocase
        $persistence = "HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" nocase
    condition:
        any of them
}

rule PE_Packer_Detection {
    meta:
        description = "Detects common packers"
    strings:
        $upx = "UPX!" ascii
        $aspack = "ASPack" ascii
        $petite = "Petite" ascii
        $pecompact = "PECompact" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}
'''
        with open(self.rules_path, 'w') as f:
            f.write(default_rules)
    
    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """فحص الملف باستخدام YARA"""
        if not self.rules:
            return [{"error": "YARA rules not loaded"}]
        
        matches = self.rules.match(file_path)
        results = []
        
        for match in matches:
            results.append({
                "rule_name": match.rule,
                "namespace": match.namespace,
                "tags": match.tags,
                "meta": match.meta,
                "strings": [
                    {
                        "identifier": s.identifier,
                        "instances": len(s.instances),
                        "matches": [str(instance) for instance in s.instances[:3]]  # أول 3 تطابقات فقط
                    }
                    for s in match.strings
                ] if match.strings else []
            })
        
        return results