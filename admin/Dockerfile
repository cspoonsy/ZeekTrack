FROM python:3.12-slim
RUN pip install --no-cache-dir fastapi uvicorn[standard] docker jinja2 python-multipart psutil
# iptables for DOCKER-USER chain manipulation
RUN apt-get update && apt-get install -y --no-install-recommends iptables && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY app.py .
COPY templates templates
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "9999"]
