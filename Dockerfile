FROM python:3.11-slim

# تثبيت التبعيات النظامية لـ YARA
RUN apt-get update && apt-get install -y \
    gcc \
    libssl-dev \
    libmagic1 \
    libmagic-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# نسخ المتطلبات وتثبيتها
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# نسخ الكود
COPY . .

# إنشاء المجلدات اللازمة
RUN mkdir -p uploads rules

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]