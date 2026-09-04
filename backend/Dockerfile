FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install lightweight CPU-only PyTorch to avoid 5+ GB of unnecessary CUDA GPU downloads
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Pre-download the HuggingFace model during build to bake it into the image cache
# This prevents the 260MB download on the first API request, removing the delay
RUN python -c "from transformers import pipeline; pipeline('text-classification', model='bixby404/phishing-detection', tokenizer='bixby404/phishing-detection')"

RUN mkdir -p /app/data

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
