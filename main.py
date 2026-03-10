import os
import shutil
from fastapi import FastAPI, File, UploadFile, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from pathlib import Path
import uuid

from app.scanner import MalwareScanner
from app.config import settings

app = FastAPI(
    title="Automated Malware Scanner",
    description="Automated malware analysis system with VirusTotal, YARA, FLOSS, and AI reporting",
    version="1.0.0"
)

scanner = MalwareScanner()

# إنشاء مجلد الرفع
os.makedirs(settings.UPLOAD_DIR, exist_ok=True)

@app.get("/")
async def root():
    return {
        "message": "Automated Malware Scanner API",
        "endpoints": {
            "upload": "POST /scan",
            "health": "GET /health"
        }
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "malware-scanner"}

@app.post("/scan")
async def scan_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="EXE, DLL, or other executable file to analyze")
):
    """
    رفع ملف وإجراء فحص شامل للبرامج الخبيثة
    """
    # التحقق من امتداد الملف
    allowed_extensions = {'.exe', '.dll', '.sys', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js'}
    file_ext = Path(file.filename).suffix.lower()
    
    if file_ext not in allowed_extensions:
        raise HTTPException(
            status_code=400,
            detail=f"File type {file_ext} not allowed. Allowed: {allowed_extensions}"
        )
    
    # إنشاء اسم فريد للملف
    unique_id = str(uuid.uuid4())[:8]
    safe_filename = f"{unique_id}_{file.filename}"
    file_path = os.path.join(settings.UPLOAD_DIR, safe_filename)
    
    try:
        # حفظ الملف
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        # التحقق من حجم الملف
        file_size = os.path.getsize(file_path)
        if file_size > settings.MAX_FILE_SIZE:
            os.remove(file_path)
            raise HTTPException(status_code=413, detail="File too large")
        
        # إجراء الفحص
        results = await scanner.scan_file(file_path, file.filename)
        
        # تنظيف الملف بعد الفحص (اختياري)
        background_tasks.add_task(cleanup_file, file_path)
        
        return JSONResponse(content={
            "success": True,
            "scan_id": unique_id,
            "filename": file.filename,
            "file_size": file_size,
            "results": results
        })
        
    except Exception as e:
        if os.path.exists(file_path):
            os.remove(file_path)
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/scan/{scan_id}")
async def get_scan_status(scan_id: str):
    """الحصول على حالة فحص سابق (يتطلب تخزين في قاعدة بيانات في الإنتاج)"""
    return {"message": "Feature requires database implementation", "scan_id": scan_id}

def cleanup_file(file_path: str):
    """تنظيف الملف بعد الفحص"""
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            print(f"[+] Cleaned up: {file_path}")
    except Exception as e:
        print(f"[-] Cleanup error: {e}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)